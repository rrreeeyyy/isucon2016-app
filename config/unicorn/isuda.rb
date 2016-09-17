worker_processes 5
preload_app true
timeout 120
stderr_path File.expand_path('/tmp/log/unicorn_stderr.log', __FILE__)
stdout_path File.expand_path('/tmp/unicorn_stdout.log', __FILE__)
