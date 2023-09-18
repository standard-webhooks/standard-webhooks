<?php

namespace StandardWebhooks\Exception;

class WebhookSigningException extends \Exception
{
    public function __construct($message, $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
