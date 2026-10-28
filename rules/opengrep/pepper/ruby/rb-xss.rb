class CommentsController < ApplicationController
  def preview
    # ruleid: pepper.rb.xss-escaping-disabled
    @body = params[:body].html_safe
    # ruleid: pepper.rb.xss-escaping-disabled
    render html: "<p>#{params[:msg]}</p>".html_safe

    # ok: pepper.rb.xss-escaping-disabled
    @clean = sanitize(params[:body]).html_safe
    # ok: pepper.rb.xss-escaping-disabled
    @static = "<b>Saved</b>".html_safe
  end
end
