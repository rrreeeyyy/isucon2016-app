require 'digest/sha1'
require 'json'
require 'net/http'
require 'uri'

require 'erubis'
require 'mysql2'
require 'mysql2-cs-bind'
require 'rack/utils'
require 'sinatra/base'
require 'tilt/erubis'
require 'rack-lineprof'
require 'redis'


module Isuda
  class Web < ::Sinatra::Base
    logger = Logger.new("/tmp/app.log-#{Time.now.strftime("%Y-%m-%d-%H-%M-%S")}")
    use Rack::Lineprof
    use Rack::CommonLogger, logger

    enable :protection
    enable :sessions

    redis = Redis.new(:host => "127.0.0.1", :port => 6379, :db => 0)
    redis_users = Redis.new(:host => "127.0.0.1", :port => 6379, :db => 1)
    TTL = 86400

    set :erb, escape_html: true
    set :public_folder, File.expand_path('../../../../public', __FILE__)
    set :db_user, ENV['ISUDA_DB_USER'] || 'root'
    set :db_password, ENV['ISUDA_DB_PASSWORD'] || ''
    set :dsn, ENV['ISUDA_DSN'] || 'dbi:mysql:db=isuda'
    set :session_secret, 'tonymoris'
    set :isupam_origin, ENV['ISUPAM_ORIGIN'] || 'http://localhost:5050'
    set :isutar_origin, ENV['ISUTAR_ORIGIN'] || 'http://localhost:5001'

    configure :development do
      require 'sinatra/reloader'

      register Sinatra::Reloader
    end

    set(:set_name) do |value|
      condition {
        user_name = session[:user_name]
        if user_name
          is_exist = redis_users.hexists('users', user_name)
          @user_name = user_name
          halt(403) unless is_exist
        end
      }
    end

    set(:authenticate) do |value|
      condition {
        halt(403) unless @user_name
      }
    end

    helpers do
      def db
        Thread.current[:db] ||=
          begin
            _, _, attrs_part = settings.dsn.split(':', 3)
            attrs = Hash[attrs_part.split(';').map {|part| part.split('=', 2) }]
            mysql = Mysql2::Client.new(
              username: settings.db_user,
              password: settings.db_password,
              database: attrs['db'],
              encoding: 'utf8mb4',
              init_command: %|SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'|,
            )
            mysql.query_options.update(symbolize_keys: true)
            mysql
          end
      end

      def register(name, pw)
        #chars = [*'A'..'~']
        #salt = 1.upto(20).map { chars.sample }.join('')
        #salted_password = encode_with_salt(password: pw, salt: salt)
        db.xquery(%|
          INSERT INTO user (name)
          VALUES (?)
        |, name)
        redis.sadd('user', name)
        name
      end

      def encode_with_salt(password: , salt: )
        Digest::SHA1.hexdigest(salt + password)
      end

      def is_spam_content(content)
        isupam_uri = URI(settings.isupam_origin)
        res = Net::HTTP.post_form(isupam_uri, 'content' => content)
        validation = JSON.parse(res.body)
        validation['valid']
        ! validation['valid']
      end

      def htmlify(content)
        keywords = db.xquery(%| select keyword from entry order by character_length(keyword) desc |)
        pattern = keywords.map {|k| Regexp.escape(k[:keyword]) }.join('|')
        kw2hash = {}
        hashed_content = content.gsub(/(#{pattern})/) {|m|
          matched_keyword = $1
          "isuda_#{Digest::SHA1.hexdigest(matched_keyword)}".tap do |hash|
            kw2hash[matched_keyword] = hash
          end
        }
        escaped_content = Rack::Utils.escape_html(hashed_content)
        kw2hash.each do |(keyword, hash)|
          keyword_url = url("/keyword/#{Rack::Utils.escape_path(keyword)}")
          anchor = '<a href="%s">%s</a>' % [keyword_url, Rack::Utils.escape_html(keyword)]
          escaped_content.gsub!(hash, anchor)
        end
        escaped_content.gsub(/\n/, "<br />\n")
      end

      def uri_escape(str)
        Rack::Utils.escape_path(str)
      end

      def load_stars(keyword)
        stars = db.xquery(%| select user_name from isutar.star where keyword = ? |, keyword).to_a
        #isutar_url = URI(settings.isutar_origin)
        #isutar_url.path = '/stars'
        #isutar_url.query = URI.encode_www_form(keyword: keyword)
        #body = Net::HTTP.get(isutar_url)
        #stars_res = JSON.parse(body)
        #stars_res['stars']
	j = JSON.generate(stars: stars)
	stars_res = JSON.parse(j)
	stars_res['stars']
      end

      def redirect_found(path)
        redirect(path, 302)
      end
    end

    get '/initialize' do
      db.xquery(%| DELETE FROM entry WHERE id > 7101 |)
      # add star 
      db.xquery('TRUNCATE isutar.star')
      #db.xquery(%| ALTER TABLE entry DROP created_at |)
      redis_users.flushdb
      users = db.xquery(%| SELECT id, name from user |)
      users.each do |user|
	      redis_users.hset('users', user[:name], user[:id])
      end
      isutar_initialize_url = URI(settings.isutar_origin)
      isutar_initialize_url.path = '/initialize'
      #Net::HTTP.get_response(isutar_initialize_url)

      content_type :json
      JSON.generate(result: 'ok')
    end

    get '/stars' do
      keyword = params[:keyword] || ''
      #stars = redis.hget("stars", keyword)
      stars = db.xquery(%| select keyword from isutar.star where keyword = ? |, keyword).to_a

      content_type :json
      JSON.generate(stars: stars)
    end

    post '/stars' do
      keyword = params[:keyword]

      #isuda_keyword_url = URI(settings.isuda_origin)
      #isuda_keyword_url.path = '/keyword/%s' % [Rack::Utils.escape_path(keyword)]
      res = db.xquery(%| select keyword from entry where keyword = ? |, keyword).to_a
      if res.empty?
          halt(404)
      end
      user_name = params[:user]
      #redis.hincrby("stars", user_name)
      db.xquery(%|
        INSERT INTO isutar.star (keyword, user_name, created_at)
        VALUES (?, ?, NOW())
      |, keyword, user_name)

      content_type :json
      JSON.generate(result: 'ok')
    end

    get '/initialize_htmlify' do
      entries = db.xquery(%| SELECT keyword, description FROM entry|)
      entries.each do |entry|
        redis.hset('entries', entry[:keyword], htmlify(entry[:description]))
      end
    end

    get '/', set_name: true do
      per_page = 10
      page = (params[:page] || 1).to_i

      entries = db.xquery(%|
        SELECT keyword, description FROM entry
        ORDER BY updated_at DESC
        LIMIT #{per_page}
        OFFSET #{per_page * (page - 1)}
      |)
      entries.each do |entry|
        if redis.hexists('entries', entry[:keyword])
          entry[:html] = redis.hget('entries', entry[:keyword])
        else
          entry[:html] = htmlify(entry[:description])
        end
        entry[:stars] = load_stars(entry[:keyword])
      end
      # entries.each do |entry|
      #   entry[:html] = htmlify(entry[:description])
      #   entry[:stars] = load_stars(entry[:keyword])
      # end

      total_entries = db.xquery(%| SELECT count(id) AS total_entries FROM entry |).first[:total_entries].to_i

      last_page = (total_entries.to_f / per_page.to_f).ceil
      from = [1, page - 5].max
      to = [last_page, page + 5].min
      pages = [*from..to]

      locals = {
        entries: entries,
        page: page,
        pages: pages,
        last_page: last_page,
      }
      erb :index, locals: locals
    end

    get '/robots.txt' do
      halt(404)
    end

    get '/register', set_name: true do
      erb :register
    end

    post '/register' do
      name = params[:name] || ''
      pw   = params[:password] || ''
      halt(400) if (name == '') || (pw == '')

      user_name = register(name, pw)
      session[:user_name] = user_name

      redirect_found '/'
    end

    get '/login', set_name: true do
      locals = {
        action: 'login',
      }
      erb :authenticate, locals: locals
    end

    post '/login' do
      name = params[:name]
      #user = db.xquery(%| select name from user where name = ? |, name).first
      is_exist = redis_users.hexists('users', name)
      halt(403) unless is_exist
      halt(403) unless params[:name] == params[:password]

      session[:user_name] = params[:name]

      redirect_found '/'
    end

    get '/logout' do
      session[:user_name] = nil
      redirect_found '/'
    end

    post '/keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] || ''
      halt(400) if keyword == ''
      description = params[:description]
      halt(400) if is_spam_content(description) || is_spam_content(keyword)

      user_id = redis.hget('users', @user_name) 
      bound = [user_id, keyword, description] * 2
      db.xquery(%|
        INSERT INTO entry (author_id, keyword, description, updated_at)
        VALUES (?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE
        author_id = ?, keyword = ?, description = ?, updated_at = NOW()
      |, *bound)
      candidate_keywords = db.xquery(%|SELECT keyword FROM entry WHERE match(description) against(?)|, params[:keyword])
      candidate_keywords.each do |keyword|
        redis.hdel('entries', keyword)
      end
      redis.hset('entries', params[:keyword], htmlify(params[:description]))

      redirect_found '/'
    end

    get '/keyword/:keyword', set_name: true do
      keyword = params[:keyword] or halt(400)

      entry = db.xquery(%| select keyword, description from entry where keyword = ? |, keyword).first or halt(404)
      if redis.hexists('entries', entry[:keyword])
        entry[:html] = redis.hget('entries', entry[:keyword])
      else
        entry[:html] = htmlify(entry[:description])
      end
      entry[:stars] = load_stars(entry[:keyword])

      locals = {
        entry: entry,
      }
      erb :keyword, locals: locals
    end

    post '/keyword/:keyword', set_name: true, authenticate: true do
      keyword = params[:keyword] or halt(400)
      is_delete = params[:delete] or halt(400)

      unless db.xquery(%| SELECT id FROM entry WHERE keyword = ? |, keyword).first
        halt(404)
      end

      db.xquery(%| DELETE FROM entry WHERE keyword = ? |, keyword)
      redis.hdel('entries', keyword)

      redirect_found '/'
    end
  end
end
