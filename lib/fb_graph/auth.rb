module FbGraph
  # = Parse & verify facebook auth cookie
  # 
  # Used with Facebook JavaScript SDK
  # 
  #   app = FbGraph::Auth.new(APP_ID, APP_SECRET)
  #   app.from_cookie(cookie_hash)
  #   auth.access_token
  #   # => OAuth2::AccessToken (not String!)
  #   auth.user # only initialized
  #   auth.user.fetch # fetch whole profile
  # 
  # This method is called automatically if cookie is given when initializing
  # 
  #   auth = FbGraph::Auth.new(APP_ID, APP_SECRET, :cookie => {..})
  #   auth.access_token # already parsed
  class Auth
    class VerificationFailed < FbGraph::Exception; end

    attr_accessor :client, :access_token, :user

    def initialize(client_id, client_secret, options = {})
      @client = OAuth2::Client.new(client_id, client_secret, options.merge(
        :site => FbGraph::ROOT_URL
      ))
      if options[:cookie].present?
        from_cookie(options[:cookie])
      end
    end

    def from_cookie(cookie)

      #this creates a cookie
      cookie = FbGraph::Auth::Cookie.parse(self.client, cookie)

      #the cookie expires time is the time as an integer
      #in the oauth2 api, it does Time.now + expires, creating a time too large
      #instead, make expires a delta value
      time_expires = cookie[:expires].to_i - Time.now.to_i
      self.access_token = OAuth2::AccessToken.new(
        self.client,
        cookie[:access_token],
        cookie[:refresh_token],
        time_expires
      )
      self.user = FbGraph::User.new(cookie[:uid], :access_token => self.access_token)
      self
    end
  end
end

require 'fb_graph/auth/cookie'
