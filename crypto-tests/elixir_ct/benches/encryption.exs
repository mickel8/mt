defmodule Benchmark do
  @header <<0x57, 0x25, 0xE7, 0x4F, 0x2D, 0x27, 0x5D, 0x12, 0x8B, 0x37, 0xB0, 0x47, 0x04, 0x16,
            0x08, 0xA1, 0x84, 0x23, 0x65, 0xDB, 0xFA, 0xE7>>
  @key <<10, 141, 102, 148, 37, 119, 128, 179, 47, 14, 68, 0, 205, 28, 26, 149>>
  @hp_key <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F>>

  def run() do
    Benchee.run(
      %{
        "payload_enc" => fn {payload, crypto_state} ->
          ElixirCt.encrypt_payload(crypto_state, @header, payload)
        end,
        "packet_enc" => fn {payload, crypto_state} ->
          ElixirCt.encrypt_pkt(crypto_state, @header, payload)
        end
      },
      before_scenario: fn payload ->
        crypto_state = ElixirCt.init(@key, @hp_key, :aes_128_gcm)
        {payload, crypto_state}
      end,
      inputs: %{
        "100" => ElixirCt.generate_payload(100),
        "200" => ElixirCt.generate_payload(200),
        "300" => ElixirCt.generate_payload(300),
        "400" => ElixirCt.generate_payload(400),
        "500" => ElixirCt.generate_payload(500),
        "600" => ElixirCt.generate_payload(600),
        "700" => ElixirCt.generate_payload(700),
        "800" => ElixirCt.generate_payload(800),
        "900" => ElixirCt.generate_payload(900),
        "1000" => ElixirCt.generate_payload(1000),
        "1100" => ElixirCt.generate_payload(1100),
        "1200" => ElixirCt.generate_payload(1200),
        "1300" => ElixirCt.generate_payload(1300)
      },
      formatters: [
        Benchee.Formatters.Console,
        {Benchee.Formatters.HTML, file: "benchee/report.html"}
      ]
    )
  end
end

Benchmark.run()
