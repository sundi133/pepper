require "net/http"
require "open-uri"

class WebhooksController < ApplicationController
  def test
    url = params[:url]
    # ruleid: pepper.rb.ssrf
    Net::HTTP.get(URI(url))
    # ruleid: pepper.rb.ssrf
    HTTParty.post(params[:callback], body: {})
    # ruleid: pepper.rb.ssrf
    URI.open(url).read

    # ok: pepper.rb.ssrf
    HTTParty.get("https://api.github.com/users/#{url}")
    # ok: pepper.rb.ssrf
    HTTParty.get("https://api.example.com/search", query: { q: url })
  end
end
