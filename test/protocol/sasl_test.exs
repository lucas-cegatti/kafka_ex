defmodule KafkaEx.Protocol.Metadata.SaslTest do
  use ExUnit.Case, async: true

  test "create_handshake_request with any mechanism creates a valid request" do
    good_request = <<17::16, 0::16, 1::32, 3::16, "foo"::binary, 4::16, "mech"::binary>>
    request = KafkaEx.Protocol.Sasl.create_handshake_request(1, "foo", 0, "mech")
    assert request == good_request
  end
end
