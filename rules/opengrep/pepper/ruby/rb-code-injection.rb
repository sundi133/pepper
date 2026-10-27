class ReportsController < ApplicationController
  ALLOWED = { "csv" => CsvReport, "pdf" => PdfReport }.freeze

  def show
    # ruleid: pepper.rb.code-injection
    klass = params[:type].constantize
    # ruleid: pepper.rb.code-injection
    @report.send(params[:action_name])
    # ruleid: pepper.rb.code-injection
    eval("1 + #{params[:n]}")
    # ruleid: pepper.rb.code-injection
    render inline: "<h1>#{params[:title]}</h1>"

    # ok: pepper.rb.code-injection
    klass2 = ALLOWED.fetch(params[:type])
    # ok: pepper.rb.code-injection
    @report.send(:generate)
    # ok: pepper.rb.code-injection
    klass3 = ALLOWED[params[:type]].new
    # ok: pepper.rb.code-injection
    render :show, locals: { title: params[:title] }
  end
end
