<?php

class ContactFormOverride extends Contactform
{
    public function sendMessage()
    {
        hook::exec('actionContactFormSubmitBefore');
        parent::sendMessage();
    }
}