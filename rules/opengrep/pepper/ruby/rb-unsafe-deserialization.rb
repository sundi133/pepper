class PrefsController < ApplicationController
  def update
    # ruleid: pepper.rb.insecure-deserialization
    prefs = Marshal.load(Base64.decode64(cookies[:prefs]))
    # ruleid: pepper.rb.insecure-deserialization
    doc = YAML.unsafe_load(request.body.read)

    # ok: pepper.rb.insecure-deserialization
    data = JSON.parse(request.body.read)
    # ok: pepper.rb.insecure-deserialization
    cfg = YAML.safe_load(params[:yaml], permitted_classes: [Date])
    # ok: pepper.rb.insecure-deserialization
    cached = Marshal.load(Rails.cache.read("k"))
  end
end
