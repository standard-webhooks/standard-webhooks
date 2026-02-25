# frozen_string_literal: true

module StandardWebhooks
  # Secure string comparison for strings of fixed length
  #
  # While a timing attack would not be able to discern the content of
  # a secret compared via secure_compare, it is possible to determine
  # the secret length. This should be considered when using secure_compare
  # to compare weak, short secrets to user input.
  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    OpenSSL.fixed_length_secure_compare(a, b)
  end

  module_function :secure_compare
end
