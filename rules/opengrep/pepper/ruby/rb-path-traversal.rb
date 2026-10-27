class DownloadsController < ApplicationController
  BASE = Rails.root.join("storage", "exports").to_s

  def show
    # ruleid: pepper.rb.path-traversal
    send_file "#{BASE}/#{params[:file]}"
    # ruleid: pepper.rb.path-traversal
    data = File.read(File.join(BASE, params[:name]))
    # ruleid: pepper.rb.path-traversal
    File.delete(params[:path])

    # ok: pepper.rb.path-traversal
    send_file File.join(BASE, File.basename(params[:file]))
    # ok: pepper.rb.path-traversal
    File.read(Rails.root.join("config", "app.yml"))
  end

  def view
    full = File.expand_path(File.join(BASE, params[:f]))
    head(:forbidden) and return unless full.start_with?(BASE + File::SEPARATOR)
    # ok: pepper.rb.path-traversal
    send_file full
  end
end
