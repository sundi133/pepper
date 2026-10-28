require "open3"
require "shellwords"

class ToolsController < ApplicationController
  def ping
    host = params[:host]
    # ruleid: pepper.rb.command-injection
    system("ping -c 1 #{host}")
    # ruleid: pepper.rb.command-injection
    out = `nslookup #{params[:d]}`
    # ruleid: pepper.rb.command-injection
    Open3.capture2("whois " + host)
    # ruleid: pepper.rb.command-injection
    IO.popen("dig #{host}").read

    # ok: pepper.rb.command-injection
    system("ping", "-c", "1", host)
    # ok: pepper.rb.command-injection
    system("ping -c 1 #{Shellwords.escape(host)}")
    # ok: pepper.rb.command-injection
    Open3.capture2("whois", host)
    # ok: pepper.rb.command-injection
    system("uptime")
  end
end

get "/run" do
  # ruleid: pepper.rb.command-injection
  system("ls #{params[:dir]}")
end
