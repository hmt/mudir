require 'google/api_client'
require 'google/api_client/client_secrets'
require 'google/api_client/auth/file_storage'
require 'sinatra/base'
require 'slim'
require 'sass'
require 'set'


class Mudir < Sinatra::Base

  CREDENTIAL_STORE_FILE = "#{$0}-oauth2.json"

  def api_client; settings.api_client; end

  def calendar_api; settings.calendar; end

  def user_credentials
    # Build a per-request oauth credential based on token stored in session
    # which allows us to use a shared API client.
    @authorization ||= (
      auth = api_client.authorization.dup
      auth.redirect_uri = to('/oauth2callback')
      auth.update_token!(session)
      auth
    )
  end

  configure do
    client = Google::APIClient.new(
      :application_name => 'Mudir, the director of access',
      :application_version => '1.0.0')

    file_storage = Google::APIClient::FileStorage.new(CREDENTIAL_STORE_FILE)
    if file_storage.authorization.nil?
      client_secrets = Google::APIClient::ClientSecrets.load
      client.authorization = client_secrets.to_authorization
      client.authorization.scope = 'https://www.googleapis.com/auth/calendar'
    else
      client.authorization = file_storage.authorization
    end

    # Since we're saving the API definition to the settings, we're only retrieving
    # it once (on server start) and saving it between requests.
    # If this is still an issue, you could serialize the object and load it on
    # subsequent runs.
    calendar = client.discovered_api('calendar', 'v3')

    set :api_client, client
    set :calendar, calendar

    set :slim, :pretty => true
    enable :sessions
    set :session_secret, ENV['mudir_secret'] ||= 'super secret'
    enable :method_override
    enable :protection
    set :public_dir, settings.root + "/public"
    enable :static
    set :views, settings.root + '/views'
  end

  configure :development do
    require 'sinatra/reloader'
  end

  helpers do
    def partial(template, locals = {})
      slim template, :layout => false, :locals => locals
    end

    def flash
      @flash = session.delete(:flash)
    end
  end

  before do
    # Ensure user has authorized the app
    unless user_credentials.access_token || request.path_info =~ /\A\/oauth2/
      redirect to('/oauth2authorize')
    end
  end

  after do
    # Serialize the access/refresh token to the session and credential store.
    session[:access_token] = user_credentials.access_token
    session[:refresh_token] = user_credentials.refresh_token
    session[:expires_in] = user_credentials.expires_in
    session[:issued_at] = user_credentials.issued_at

    file_storage = Google::APIClient::FileStorage.new(CREDENTIAL_STORE_FILE)
    file_storage.write_credentials(user_credentials)
  end

  get '/oauth2authorize' do
    # Request authorization
    redirect user_credentials.authorization_uri.to_s, 303
  end

  get '/oauth2callback' do
    # Exchange token
    user_credentials.code = params[:code] if params[:code]
    user_credentials.fetch_access_token!
    redirect to('/')
  end

  get '/css/:file.css' do
    halt 404 unless File.exist?("views/#{params[:file]}.scss")
    time = File.stat("views/#{params[:file]}.scss").ctime
    last_modified(time)
    scss params[:file].intern
  end

  get '/' do
    # Fetch list of events on the user's default calandar
    result = api_client.execute(:api_method => calendar_api.calendar_list.list,
                                :authorization => user_credentials)

    #save all users mentioned in calendars in a set
    users = Set.new
    cal_scopes = result.data.items.map do |i|
      #skip calendar if primary or not owned by user (cannot be changed anyway)
      next if i.primary || i.accessRole != "owner"
      r = api_client.execute(:api_method => calendar_api.acl.list,
                             :parameters => {'calendarId' => i.id})
      #capture all calendars and their acls and map it to an Array
      {i.summary => r.data.items.map { |ii| users.add(ii.scope['value']) unless i.id == ii.scope['value']; {ii.scope['value'] => ii.role}}}
    end
    #remove skipped entries (=nil)
    cal_scopes.compact!
    slim :home, :locals => { :result => result, :cal_scopes => cal_scopes, :users => users }
  end

  patch '/update' do
    # Change access to calendars according to settings
    params[:cal].each_pair do |calendar, role|
      rule = {
        'scope' => {
          'type' => 'user',
          'value' => params[:email],
        },
        'role' => role
      }
      api_client.execute(:api_method => calendar_api.acl.insert,
                              :parameters => {'calendarId' => calendar},
                              :body => JSON.dump(rule),
                              :headers => {'Content-Type' => 'application/json'})
    end
    session[:flash] = ["Benutzer #{params[:email]} wurde angelegt bzw. geändert", "alert-success"]
    redirect '/'
  end
end

