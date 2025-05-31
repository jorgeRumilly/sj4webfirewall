<?php
use PrestaShop\PrestaShop\Adapter\SymfonyContainer;

class FirewallMailer
{
    public static function sendAlert($ip, $userAgent, $score, $country = 'N/A')
    {

        if (!Configuration::get('SJ4WEB_FW_ALERT_EMAIL_ENABLED')) {
            return; // Alertes désactivées
        }
//        $translator = SymfonyContainer::getInstance()->get('translator');
        $translator = \Context::getContext()->getTranslator();
        $recipients = Configuration::get('SJ4WEB_FW_ALERT_RECIPIENTS');

        if ($recipients) {
            $emails = array_map('trim', explode(',', $recipients));
        } else {
            $emails = [Configuration::get('PS_SHOP_EMAIL')];
        }

        $langId = (int)Configuration::get('PS_LANG_DEFAULT');
        $shopId = (int)Context::getContext()->shop->id;

        $templateVars = [
            '{ip}' => $ip,
            '{user_agent}' => $userAgent,
            '{score}' => $score,
            '{country}' => $country,
        ];

        $subject = $translator->trans('Firewall Alert - Suspicious Activity Detected', [], 'Modules.Sj4webfirewall.Admin');

        return Mail::send(
            $langId,
            'sj4webfirewall_alert',
            $subject,
            $templateVars,
            $emails,
            null, // to name
            Configuration::get('PS_SHOP_EMAIL'), // from email
            Configuration::get('PS_SHOP_NAME'), // from name
            null, // file attachment
            null, // mode SMTP
            _PS_MODULE_DIR_ . 'sj4webfirewall/mails/',
            false,
            $shopId
        );
    }
}