worker_processes 5
preload_app true
timeout 12000000
listen "/home/isucon/unicorn.sock"
#stderr_path File.expand_path('/tmp/log/unicorn_stderr.log', __FILE__)
#stdout_path File.expand_path('/tmp/unicorn_stdout.log', __FILE__)
log = '/tmp/unicorn.log'
stderr_path '/tmp/unicorn.log'
stdout_path '/tmp/unicorn.log'
