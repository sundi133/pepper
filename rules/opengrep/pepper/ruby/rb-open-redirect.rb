class SessionsController < ApplicationController
  def create
    # ruleid: pepper.rb.open-redirect
    redirect_to params[:return_to]
  end

  def back
    # ruleid: pepper.rb.open-redirect
    redirect_to request.referer
  end

  def safe
    # ok: pepper.rb.open-redirect
    redirect_to params[:return_to], allow_other_host: false
  end

  def safe2
    # ok: pepper.rb.open-redirect
    redirect_to url_from(params[:return_to]) || root_path
  end

  def tab
    # ok: pepper.rb.open-redirect
    redirect_to "/profile/#{params[:tab]}"
  end

  def download
    upload = Upload.find(params[:id])
    # ok: pepper.rb.open-redirect
    redirect_to upload.url
  end

  def invite
    # ok: pepper.rb.open-redirect
    redirect_to new_user_registration_path(params.permit(:invite_code))
  end
end

class ToggleSetting
  def call
    # ok: pepper.rb.open-redirect
    redirect_to params[:url]
  end
end
