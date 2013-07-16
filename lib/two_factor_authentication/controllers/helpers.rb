module TwoFactorAuthentication
  module Controllers
    module Helpers
      extend ActiveSupport::Concern

      included do
        before_filter :handle_two_factor_authentication
      end

      private

      def handle_two_factor_authentication
        unless devise_controller?
          scope = 'admin_user'
          if signed_in?(scope) and warden.session(scope)[:need_two_factor_authentication]
            handle_failed_second_factor(scope)
          end
        end
      end

      def handle_failed_second_factor(scope)
        if request.format.present? and request.format.html?
          session["#{scope}_return_tor"] = request.path if request.get?
          redirect_to two_factor_authentication_path_for(scope)
        else
          render nothing: true, status: :unauthorized
        end
      end

      def two_factor_authentication_path_for(resource_or_scope = nil)
        scope = 'admin_user'
        change_path = "#{scope}_two_factor_authentication_path"
        send(change_path)
      end

    end
  end
end
