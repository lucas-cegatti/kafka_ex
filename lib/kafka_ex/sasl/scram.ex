defmodule KafkaEx.Sasl.Scram do
  @hash_length 32
  @nonce_length 24
  @nonce_rand_bytes div(@nonce_length * 6, 8)

  def challenge() do
    @nonce_rand_bytes |> :crypto.strong_rand_bytes() |> Base.encode64()
  end

  def verify(data, sasl) do
    server =
      for kv <- :binary.split(data, ",", [:global]), into: %{} do
        <<k, "=", v::binary>> = kv
        {k, v}
      end

    {:ok, server_s} = Base.decode64(server[?s])
    server_i = String.to_integer(server[?i])

    encryption_type =
      get_encryption_from_mechanism(
        String.upcase(Keyword.fetch!(sasl, :mechanism))
      )

    pass = Keyword.fetch!(sasl, :password)
    username = Keyword.fetch!(sasl, :username)
    salted_pass = hash_password(encryption_type, pass, server_s, server_i)

    client_key = :crypto.hmac(encryption_type, salted_pass, "Client Key")
    client_nonce = binary_part(server[?r], 0, @nonce_length)

    message = [
      "n=",
      username,
      ",r=",
      client_nonce,
      ",r=",
      server[?r],
      ",s=",
      server[?s],
      ",i=",
      server[?i],
      ?,
    ]

    message_without_proof = ["c=biws,r=", server[?r]]

    auth_message = IO.iodata_to_binary([message | message_without_proof])

    client_sig =
      :crypto.hmac(
        encryption_type,
        :crypto.hash(encryption_type, client_key),
        auth_message
      )

    proof = Base.encode64(:crypto.exor(client_key, client_sig))
    [message_without_proof, ",p=", proof]
  end

  defp hash_password(encryption_type, secret, salt, iterations) do
    hash_password(encryption_type, secret, salt, iterations, 1, [], 0)
  end

  defp get_encryption_from_mechanism("SCRAM-SHA-256"), do: :sha256

  defp get_encryption_from_mechanism("SCRAM-SHA-512"), do: :sha512

  defp hash_password(
         _encryption_type,
         _secret,
         _salt,
         _iterations,
         _block_index,
         acc,
         length
       )
       when length >= @hash_length do
    acc
    |> IO.iodata_to_binary()
  end

  defp hash_password(
         encryption_type,
         secret,
         salt,
         iterations,
         block_index,
         acc,
         length
       ) do
    initial =
      :crypto.hmac(
        encryption_type,
        secret,
        <<salt::binary, block_index::integer-size(32)>>
      )

    block = iterate(encryption_type, secret, iterations - 1, initial, initial)
    length = byte_size(block) + length

    hash_password(
      encryption_type,
      secret,
      salt,
      iterations,
      block_index + 1,
      [acc | block],
      length
    )
  end

  defp iterate(_encryption_type, _secret, 0, _prev, acc), do: acc

  defp iterate(encryption_type, secret, iteration, prev, acc) do
    next = :crypto.hmac(encryption_type, secret, prev)

    iterate(
      encryption_type,
      secret,
      iteration - 1,
      next,
      :crypto.exor(next, acc)
    )
  end
end
