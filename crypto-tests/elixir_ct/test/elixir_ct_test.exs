defmodule ElixirCtTest do
  use ExUnit.Case

  @header <<0x57, 0x25, 0xE7, 0x4F, 0x2D, 0x27, 0x5D, 0x12, 0x8B, 0x37, 0xB0, 0x47, 0x04, 0x16,
            0x08, 0xA1, 0x84, 0x23, 0x65, 0xDB, 0xFA, 0xE7>>

  @key <<10, 141, 102, 148, 37, 119, 128, 179, 47, 14, 68, 0, 205, 28, 26, 149>>

  @hp_key <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F>>

  test "encrypt header" do
    payload = ElixirCt.generate_payload(100)
    crypto_state = ElixirCt.init(@key, @hp_key, :aes_128_gcm)
    enc_payload = ElixirCt.encrypt_payload(crypto_state, @header, payload)
    ElixirCt.encrypt_hdr(crypto_state, enc_payload, @header)
  end

  test "encrypt payload" do
    payload = ElixirCt.generate_payload(100)
    crypto_state = ElixirCt.init(@key, @hp_key, :aes_128_gcm)
    ElixirCt.encrypt_payload(crypto_state, @header, payload)
  end
end
