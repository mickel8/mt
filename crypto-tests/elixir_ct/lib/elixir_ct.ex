defmodule ElixirCt do
  use Bitwise

  @opaque t() :: %__MODULE__{
            key: binary(),
            hp_key: binary(),
            nonce: binary(),
            algorithm: :aes_gcm_128
          }

  defstruct key: <<>>,
            hp_key: <<>>,
            nonce: <<>>,
            algorithm: :aes_gcm_128

  @spec init(binary(), binary(), binary()) :: ElixirCt.t()
  def init(key, hp_key, algorithm) do
    %__MODULE__{
      key: key,
      hp_key: hp_key,
      # TODO check size of nonce
      nonce: <<0::96>>,
      algorithm: algorithm
    }
  end

  def encrypt_pkt(state, header, payload) do
    enc_payload = encrypt_payload(state, header, payload)
    enc_header = encrypt_hdr(state, enc_payload, header)
    enc_header <> enc_payload
  end

  def encrypt_hdr(state, payload, header) do
    pn_len = 1
    sample = binary_part(payload, 4 - pn_len, 16)
    mask = new_mask(state.hp_key, sample)
    rest_len = byte_size(header) - 1 - pn_len
    <<first::8, rest::binary-size(rest_len), pn::binary-size(pn_len)>> = header
    first = first ^^^ (:binary.at(mask, 0) &&& 0x1F)

    pn =
      for i <- 0..(pn_len - 1), into: <<>>, do: <<:binary.at(pn, i) ^^^ :binary.at(mask, i + 1)>>

    <<first>> <> rest <> pn
  end

  def encrypt_payload(state, header, payload) do
    {enc_payload, tag} =
      :crypto.crypto_one_time_aead(state.algorithm, state.key, state.nonce, payload, header, true)

    enc_payload <> tag
  end

  def generate_payload(size) do
    for _i <- 0..size, into: <<>>, do: <<Enum.random(0..255)>>
  end

  def new_mask(hp_key, sample) do
    :crypto.crypto_one_time(:aes_128_ecb, hp_key, sample, true)
    |> binary_part(0, 5)
  end
end
