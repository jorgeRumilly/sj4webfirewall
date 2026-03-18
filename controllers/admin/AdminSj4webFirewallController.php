<?php

require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/Sj4webFirewallConfigHelper.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/Sj4webFirewallUserAgentMatcher.php';

class AdminSj4webFirewallController extends ModuleAdminController
{
    public function __construct()
    {
        $this->bootstrap = true;
        $this->module = Module::getInstanceByName('sj4webfirewall');
        $this->className = 'Sj4webFirewall';
        $this->lang = false;
        $this->context = Context::getContext();
        $this->table = 'sj4webfirewall';
        $this->displayName = $this->module->displayName;

        parent::__construct();
    }

    public function initContent()
    {
        parent::initContent();

        $this->context->smarty->assign([
            'content' => $this->renderForm(),
        ]);
    }

    /**
     * Affiche le formulaire de configuration du module dans le BO.
     */
    public function renderForm()
    {
        $htmlRenderContactFormNotice = '<div class="alert alert-info">';
        $htmlRenderContactFormNotice .= $this->context->smarty->fetch($this->module->getLocalPath() . 'views/templates/admin/sj4web_firewall/_contactform_help.tpl');
        $htmlRenderContactFormNotice .= '</div>';

        $fieldsForm = [
            'form' => [
                'legend' => [
                    'title' => $this->trans('Configuration du pare-feu', [], 'Modules.Sj4webfirewall.Admin'),
                ],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Activer le firewall', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_ACTIVATE_FIREWALL',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'firewall_on', 'value' => 1, 'label' => $this->trans('Yes', [], 'Modules.Sj4webfirewall.Admin')],
                            ['id' => 'firewall_off', 'value' => 0, 'label' => $this->trans('No', [], 'Modules.Sj4webfirewall.Admin')],
                        ],
                        'desc' => $this->trans('When disabled, the module keeps tracking traffic but does not apply blocking or slowdown actions.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('IP autorisees (whitelist)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_WHITELIST_IPS',
                        'cols' => 60,
                        'rows' => 5,
                        'desc' => $this->trans('One IP or CIDR range per line.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Bots autorises (safe bots)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_SAFEBOTS',
                        'cols' => 60,
                        'rows' => 7,
                        'desc' => $this->trans('One user-agent signature per line. Known social preview and major crawler signatures are kept automatically.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Bots bloques (malicious bots)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_MALICIOUSBOTS',
                        'cols' => 60,
                        'rows' => 10,
                        'desc' => $this->trans('One suspicious user-agent signature per line. Unsafe legacy patterns are removed automatically on save.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'html',
                        'name' => 'html_thresholds',
                        'html_content' => '<p>&nbsp;</p><hr><h3>' . $this->trans('Trigger thresholds', [], 'Modules.Sj4webfirewall.Admin') . '</h3>',
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Score threshold for blocking', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_SCORE_LIMIT_BLOCK',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Alert threshold', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_ALERT_THRESHOLD',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->trans('Trigger an email alert when an IP score drops below this value.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Blocking duration (s)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_BLOCK_DURATION',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Activer le ralentissement (sleep)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_ENABLE_SLEEP',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'sleep_on', 'value' => 1, 'label' => $this->trans('Yes', [], 'Modules.Sj4webfirewall.Admin')],
                            ['id' => 'sleep_off', 'value' => 0, 'label' => $this->trans('No', [], 'Modules.Sj4webfirewall.Admin')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Duree du sleep (ms)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_SLEEP_DELAY_MS',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Enable detailed text log', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_LOG_ENABLED',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'log_on', 'value' => 1, 'label' => $this->trans('Yes', [], 'Modules.Sj4webfirewall.Admin')],
                            ['id' => 'log_off', 'value' => 0, 'label' => $this->trans('No', [], 'Modules.Sj4webfirewall.Admin')],
                        ],
                        'desc' => $this->trans('Keep disabled in production unless you need a temporary forensic log file.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'html',
                        'name' => 'html_retention',
                        'html_content' => '<p>&nbsp;</p><hr><h3>' . $this->trans('Data retention', [], 'Modules.Sj4webfirewall.Admin') . '</h3>',
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Tracked IP retention (days)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_STATE_RETENTION_DAYS',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->trans('Inactive IP state rows older than this delay are purged automatically once per day.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Detailed event retention (days)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_EVENT_RETENTION_DAYS',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->trans('Detailed runtime events are purged automatically after this delay.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Contact attempt retention (days)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_CONTACT_RETENTION_DAYS',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->trans('Contact form anti-spam traces are purged automatically after this delay.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Daily stats retention (days)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_STATS_RETENTION_DAYS',
                        'class' => 'fixed-width-sm',
                        'desc' => $this->trans('Aggregated daily statistics are purged automatically after this delay.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'html',
                        'name' => 'html_countries',
                        'html_content' => '<p>&nbsp;</p><hr><h3>' . $this->trans('Block by countries', [], 'Modules.Sj4webfirewall.Admin') . '</h3>',
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Pays a bloquer (codes ISO alpha-2)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_COUNTRIES_BLOCKED',
                        'cols' => 60,
                        'rows' => 3,
                        'desc' => $this->trans('Example: RU, CN, IR.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'html',
                        'name' => 'html_contact',
                        'html_content' => '<p>&nbsp;</p><hr><h3>' . $this->trans('Contact form protection', [], 'Modules.Sj4webfirewall.Admin') . '</h3>',
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Activate contact form protection', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_CONTACT_PROTECTION_ENABLED',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'contact_on', 'value' => 1, 'label' => $this->trans('Yes', [], 'Admin.Global')],
                            ['id' => 'contact_off', 'value' => 0, 'label' => $this->trans('No', [], 'Admin.Global')],
                        ],
                        'desc' => $this->trans('Enable anti-spam checks on the contact form: honeypot, timer and rate limits.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'html',
                        'name' => 'SJ4WEB_FW_CONTACTFORM_NOTICE',
                        'label' => $this->trans('Important: manual integration required', [], 'Modules.Sj4webfirewall.Admin'),
                        'html_content' => $htmlRenderContactFormNotice,
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Max contact form messages per day (same IP)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_CONTACT_MAX_DAILY',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Max messages per period (non logged-in visitors)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_CONTACT_MAX_PER_PERIOD',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Period duration in minutes', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_CONTACT_PERIOD_MINUTES',
                        'class' => 'fixed-width-sm',
                    ],
                    [
                        'type' => 'html',
                        'name' => 'html_email',
                        'html_content' => '<p>&nbsp;</p><hr><h3>' . $this->trans('Email alerts', [], 'Modules.Sj4webfirewall.Admin') . '</h3>',
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Enable email alerts', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_ALERT_EMAIL_ENABLED',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'alert_on', 'value' => 1, 'label' => $this->trans('Yes', [], 'Modules.Sj4webfirewall.Admin')],
                            ['id' => 'alert_off', 'value' => 0, 'label' => $this->trans('No', [], 'Modules.Sj4webfirewall.Admin')],
                        ],
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Alert recipient emails', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_ALERT_RECIPIENTS',
                        'rows' => 5,
                        'desc' => $this->trans('Separate multiple email addresses with commas.', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                ],
                'submit' => [
                    'title' => $this->trans('Enregistrer', [], 'Modules.Sj4webfirewall.Admin'),
                ],
            ],
        ];

        $values = Sj4webFirewallConfigHelper::getAll();
        foreach (Sj4webFirewallConfigHelper::getMultilineKeys() as $key) {
            if (isset($values[$key]) && is_array($values[$key])) {
                $values[$key] = implode("\n", $values[$key]);
            }
        }

        $logLink = $this->context->link->getAdminLink('AdminSj4webFirewallLog');
        $statsLink = $this->context->link->getAdminLink('AdminSj4webFirewallStats');

        $html = '<div style="margin-bottom:15px;">';
        $html .= '<a href="' . $logLink . '" class="btn btn-default" target="_blank" style="margin-right:8px;">';
        $html .= '<i class="icon icon-eye"></i> ' . $this->trans('Consulter les IP bloquees / scorees', [], 'Modules.Sj4webfirewall.Admin') . '</a>';
        $html .= '<a href="' . $statsLink . '" class="btn btn-default" target="_blank">';
        $html .= '<i class="icon icon-bar-chart"></i> ' . $this->trans('Consulter les stats journalieres', [], 'Modules.Sj4webfirewall.Admin') . '</a>';
        $html .= '</div>';

        $helper = new HelperForm();
        $helper->module = $this->module;
        $helper->show_toolbar = false;
        $helper->table = $this->table;
        $helper->identifier = $this->identifier;
        $helper->currentIndex = $this->context->link->getAdminLink('AdminSj4webFirewall', false);
        $helper->token = Tools::getAdminTokenLite('AdminSj4webFirewall');
        $helper->submit_action = 'submit_sj4webfirewall';
        $helper->fields_value = $values;

        return $html . $helper->generateForm([$fieldsForm]);
    }

    /**
     * Traite l'enregistrement de la configuration.
     */
    public function postProcess()
    {
        if (!Tools::isSubmit('submit_sj4webfirewall')) {
            return;
        }

        foreach (Sj4webFirewallConfigHelper::getKeys() as $key) {
            if ($key === 'SJ4WEB_FW_LAST_CLEANUP_AT') {
                continue;
            }

            $value = Tools::getValue($key);

            if (in_array($key, Sj4webFirewallConfigHelper::getMultilineKeys(), true)) {
                $value = array_filter(array_map('trim', explode("\n", (string) $value)));

                if ($key === 'SJ4WEB_FW_SAFEBOTS') {
                    $value = Sj4webFirewallUserAgentMatcher::mergeRecommendedSafeBots($value);
                } elseif ($key === 'SJ4WEB_FW_MALICIOUSBOTS') {
                    $value = Sj4webFirewallUserAgentMatcher::sanitizeList($value, 'malicious');
                }

                $value = json_encode(array_values($value));
            } elseif (in_array($key, $this->getIntegerKeys(), true)) {
                $value = (int) $value;
            }

            Configuration::updateValue($key, $value);
        }

        $this->confirmations[] = $this->trans('Configuration enregistree', [], 'Modules.Sj4webfirewall.Admin');
    }

    /**
     * Retourne les cles numeriques a caster avant sauvegarde.
     *
     * @return array<int, string>
     */
    protected function getIntegerKeys()
    {
        return [
            'SJ4WEB_FW_ENABLE_SLEEP',
            'SJ4WEB_FW_ACTIVATE_FIREWALL',
            'SJ4WEB_FW_SLEEP_DELAY_MS',
            'SJ4WEB_FW_STATE_RETENTION_DAYS',
            'SJ4WEB_FW_EVENT_RETENTION_DAYS',
            'SJ4WEB_FW_CONTACT_RETENTION_DAYS',
            'SJ4WEB_FW_STATS_RETENTION_DAYS',
            'SJ4WEB_FW_SCORE_LIMIT_SLOW',
            'SJ4WEB_FW_BLOCK_DURATION',
            'SJ4WEB_FW_SCORE_LIMIT_BLOCK',
            'SJ4WEB_FW_LOG_ENABLED',
            'SJ4WEB_FW_ALERT_EMAIL_ENABLED',
            'SJ4WEB_FW_ALERT_THRESHOLD',
            'SJ4WEB_FW_CONTACT_PROTECTION_ENABLED',
            'SJ4WEB_FW_CONTACT_MAX_PER_PERIOD',
            'SJ4WEB_FW_CONTACT_PERIOD_MINUTES',
            'SJ4WEB_FW_CONTACT_MAX_DAILY',
        ];
    }
}
