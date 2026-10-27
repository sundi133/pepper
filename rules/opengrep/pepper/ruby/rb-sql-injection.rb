class UsersController < ApplicationController
  def index
    # ruleid: pepper.rb.sql-injection
    @users = User.where("name = '#{params[:name]}'")
    # ruleid: pepper.rb.sql-injection
    User.find_by_sql("SELECT * FROM users WHERE email = '" + params[:email] + "'")
    # ruleid: pepper.rb.sql-injection
    User.order("created_at #{params[:dir]}")
    # ruleid: pepper.rb.sql-injection
    ActiveRecord::Base.connection.execute("DELETE FROM sessions WHERE token = '#{cookies[:t]}'")

    # ok: pepper.rb.sql-injection
    User.where("name = ?", params[:name])
    # ok: pepper.rb.sql-injection
    User.where(name: params[:name])
    # ok: pepper.rb.sql-injection
    User.where("id = #{params[:id].to_i}")
    # ok: pepper.rb.sql-injection
    User.find_by_sql(["SELECT * FROM users WHERE email = ?", params[:email]])
    # ok: pepper.rb.sql-injection
    User.order(:created_at)
    # ruleid: pepper.rb.sql-injection
    User.find_by_sql(["SELECT * FROM users WHERE role = '#{params[:role]}' AND id = ?", 1])
  end
end
