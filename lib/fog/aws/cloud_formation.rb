require 'fog/aws'

module Fog
  module AWS
    class CloudFormation < Fog::Service
      extend Fog::AWS::CredentialFetcher::ServiceMethods

      requires :aws_access_key_id, :aws_secret_access_key
      recognizes :host, :path, :port, :scheme, :persistent, :region, :use_iam_profile, :aws_session_token, :aws_credentials_expire_at

      request_path 'fog/aws/requests/cloud_formation'
      request :create_stack
      request :update_stack
      request :delete_stack
      request :describe_stack_events
      request :describe_stack_resources
      request :describe_stacks
      request :get_template
      request :validate_template

      class Mock

        class Response
          def initialize status, body
            @body = body
            @status = status
          end
        end

        def initialize(options={})
          @stacks = []
          setup_credentials(options)
        end

        def setup_credentials(options)
          @aws_access_key_id ||= options[:aws_access_key_id]
          @aws_secret_access_key ||= options[:aws_secret_access_key]
        end

        def describe_stacks options = {}
          Response.new(200, generate_response(options))
        end

        def create_stack(server_name, options)
          @stacks << fake_stack(server_name, options)
          Response.new(200, generate_response(options))
        end

        def delete_stack(server_name)
          stack = @stacks.find{|el| el["StackName"] == server_name}
          if stack 
            @stacks.delete_at(@stacks.index(stack))
            Response.new(200, generate_response(options))
          else
            Response.new(500, generate_response(options))
          end
        end

        private
        def fake_stack(server_name, options)
          {
            "Outputs" => [
              {"OutputValue" => "ec2-54-242-31-112.compute-1.amazonaws.com", "OutputKey"=>"WebsiteURL"}, 
              {"OutputValue" => @aws_access_key_id, "OutputKey"=>"AccessKey"}, 
              {"OutputValue" => @aws_secret_access_key, "OutputKey"=>"SecretKey"}, 
              {"OutputValue" => "#{@server_name}-ov-s3bucket-e6410r2rz7ud", "OutputKey"=>"S3BucketName"}
            ],
            "Parameters" => [
              {"ParameterValue" => options["Parameters"]["SecurityGroup"], "ParameterKey"=>"SecurityGroup"}, 
              {"ParameterValue" => options["Parameters"]["ChefDefaultRole"], "ParameterKey"=>"ChefDefaultRole"}, 
              {"ParameterValue" => options["Parameters"]["StorageCapacity"], "ParameterKey"=>"StorageCapacity"}, 
              {"ParameterValue" => options["Parameters"]["ChefServerUrl"], "ParameterKey"=>"ChefServerUrl"}, 
              {"ParameterValue" => options["Parameters"]["KeyName"], "ParameterKey"=>"KeyName"}, 
              {"ParameterValue" => options["Parameters"]["InstanceType"], "ParameterKey"=>"InstanceType"}, 
              {"ParameterValue" => options["Parameters"]["ChefNodeName"], "ParameterKey"=>"ChefNodeName"}, 
              {"ParameterValue" => options["Parameters"]["AmiId"], "ParameterKey"=>"AmiId"}
            ], 
            "Capabilities" => options["Capabilities"], 
            "StackId" => "arn:aws:cloudformation:us-east-1:871928509102:stack/handlers001-OV/da62bbc0-236c-11e2-9a07-502554c56486", 
            "StackStatus" => "CREATE_COMPLETE", 
            "StackName" => server_name, 
            "CreationTime" => Time.now, 
            "DisableRollback" => false
          }
        end

        def generate_response options
          @body = {
            'Stacks' => (option['StackName'] ? @stacks.find_all {|stack| stack["StackName"] == option['StackName']} : @stacks), 
            'StackId' => ''
          }
        end

      end


      class Real
        include Fog::AWS::CredentialFetcher::ConnectionMethods
        # Initialize connection to CloudFormation
        #
        # ==== Notes
        # options parameter must include values for :aws_access_key_id and
        # :aws_secret_access_key in order to create a connection
        #
        # ==== Examples
        #   cf = CloudFormation.new(
        #    :aws_access_key_id => your_aws_access_key_id,
        #    :aws_secret_access_key => your_aws_secret_access_key
        #   )
        #
        # ==== Parameters
        # * options<~Hash> - config arguments for connection.  Defaults to {}.
        #
        # ==== Returns
        # * CloudFormation object with connection to AWS.
        def initialize(options={})
          require 'fog/core/parser'

          @use_iam_profile = options[:use_iam_profile]
          setup_credentials(options)

          @connection_options = options[:connection_options] || {}
          options[:region] ||= 'us-east-1'
          @host = options[:host] || "cloudformation.#{options[:region]}.amazonaws.com"
          @path       = options[:path]        || '/'
          @persistent = options[:persistent]  || false
          @port       = options[:port]        || 443
          @scheme     = options[:scheme]      || 'https'
          @connection = Fog::Connection.new("#{@scheme}://#{@host}:#{@port}#{@path}", @persistent, @connection_options)
        end

        def reload
          @connection.reset
        end

        private

        def setup_credentials(options)
          @aws_access_key_id      = options[:aws_access_key_id]
          @aws_secret_access_key  = options[:aws_secret_access_key]
          @aws_session_token      = options[:aws_session_token]
          @aws_credentials_expire_at = options[:aws_credentials_expire_at]

          @hmac       = Fog::HMAC.new('sha256', @aws_secret_access_key)
        end

        def request(params)
          refresh_credentials_if_expired

          idempotent  = params.delete(:idempotent)
          parser      = params.delete(:parser)

          body = Fog::AWS.signed_params(
            params,
            {
              :aws_access_key_id  => @aws_access_key_id,
              :aws_session_token  => @aws_session_token,
              :hmac               => @hmac,
              :host               => @host,
              :path               => @path,
              :port               => @port,
              :version            => '2010-05-15'
            }
          )

          begin
            response = @connection.request({
              :body       => body,
              :expects    => 200,
              :idempotent => idempotent,
              :headers    => { 'Content-Type' => 'application/x-www-form-urlencoded' },
              :host       => @host,
              :method     => 'POST',
              :parser     => parser
            })
          rescue Excon::Errors::HTTPStatusError => error
            if match = error.message.match(/<Code>(.*)<\/Code><Message>(.*)<\/Message>/)
              raise case match[1].split('.').last
              when 'NotFound'
                Fog::AWS::Compute::NotFound.slurp(error, match[2])
              else
                Fog::AWS::Compute::Error.slurp(error, "#{match[1]} => #{match[2]}")
              end
            else
              raise error
            end
          end

          response
        end

      end
    end
  end
end
