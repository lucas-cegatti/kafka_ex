defmodule KafkaEx.Protocol.Sasl do
  import KafkaEx.Protocol.Common
  # @supported_versions_range {0, 1}

  def create_handshake_request(
        correlation_id,
        client_id,
        api_version,
        mechanism
      ) do
    KafkaEx.Protocol.create_request(
      :sasl,
      correlation_id,
      client_id,
      api_version
    ) <> encode_string(mechanism)
  end

  def create_client_first_message(
        correlation_id,
        client_id,
        api_version,
        username,
        nonce
      ) do
    client_first_message = "n,,n=#{username},r=#{nonce}"

    KafkaEx.Protocol.create_request(
      :sasl_authenticate,
      correlation_id,
      client_id,
      api_version
    ) <>
      <<byte_size(client_first_message)::32-signed,
        client_first_message::binary>>
  end

  def create_intermediate_sasl_request(
        correlation_id,
        client_id,
        api_version,
        message
      ) do
    KafkaEx.Protocol.create_request(
      :sasl_authenticate,
      correlation_id,
      client_id,
      api_version
    ) <> <<byte_size(message)::32-signed, message::binary>>
  end

  defmodule SaslAuthenticateResponse do
    defstruct error_code: 0,
              error_message: "",
              auth_bytes: "",
              session_lifetime_ms: 0

    @type t :: %SaslAuthenticateResponse{
            error_code: integer(),
            error_message: binary(),
            auth_bytes: binary(),
            session_lifetime_ms: integer()
          }

    def parse_response(
          <<_correlation_id::32-signed, error_code::16-signed,
            error_message_len::16-signed,
            error_message::size(error_message_len)-binary,
            auth_bytes_len::32-signed, auth_bytes::size(auth_bytes_len)-binary>>
        ) do
      %__MODULE__{
        error_code: error_code,
        error_message: error_message,
        auth_bytes: auth_bytes,
        session_lifetime_ms: 0
      }
    end

    def parse_response(
          <<_correlation_id::32-signed, error_code::16-signed, -1::16-signed,
            auth_bytes_len::32-signed, auth_bytes::size(auth_bytes_len)-binary>>
        ) do
      %__MODULE__{
        error_code: error_code,
        error_message: nil,
        auth_bytes: auth_bytes,
        session_lifetime_ms: 0
      }
    end
  end

  defmodule SaslHandshakeResponse do
    defstruct error_code: 0, mechanisms: ""

    @type t :: %SaslHandshakeResponse{
            error_code: integer(),
            mechanisms: binary()
          }

    def parse_response(
          <<_correlation_id::32-signed, error_code::16-signed,
            mechanisms_len::32-signed, rest::binary()>>
        ) do
      %__MODULE__{
        error_code: error_code,
        mechanisms: parse_mechanisms(mechanisms_len, [], rest)
      }
    end

    defp parse_mechanisms(0, mechanisms, _), do: mechanisms

    defp parse_mechanisms(
           mechanisms_len,
           mechanisms,
           <<mechanism_len::16-signed, mechanism::size(mechanism_len)-binary,
             rest::binary()>>
         ) do
      parse_mechanisms(
        mechanisms_len - 1,
        [mechanism | mechanisms],
        rest
      )
    end
  end
end
