defmodule ElixirCt.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_ct,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:benchee, "~> 1.0.1"},
      {:benchee_html, "~> 1.0", only: :dev}
    ]
  end
end
