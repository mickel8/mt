defmodule ElixirCtTest do
  use ExUnit.Case
  doctest ElixirCt

  test "greets the world" do
    assert ElixirCt.hello() == :world
  end
end
