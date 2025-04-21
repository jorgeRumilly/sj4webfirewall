<?php
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/Sj4webFirewallConfigHelper.php';

class AdminSj4webFirewallController extends ModuleAdminController
{
    public function __construct()
    {
        $this->bootstrap = true;
        $this->module = Module::getInstanceByName('sj4webfirewall');
        $this->className = 'Sj4webFirewall';
        $this->lang = false;
        $this->context = Context::getContext();
        $this->table = 'sj4webfirewall'; // pas utilisé ici, mais requis par Presta
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
        $fields_form = [
            'form' => [
                'legend' => [
                    'title' => $this->trans('Configuration du pare-feu', [], 'Modules.Sj4webfirewall.Admin'),
                ],
                'input' => [
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('IP autorisées (whitelist)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_WHITELIST_IPS',
                        'cols' => 60,
                        'rows' => 5,
                        'desc' => $this->trans('Une IP ou un range CIDR par ligne', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Bots autorisés (safeBots)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_SAFEBOTS',
                        'cols' => 60,
                        'rows' => 5,
                        'desc' => $this->trans('User-Agent contenant un identifiant autorisé', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Bots bloqués (maliciousBots)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_MALICIOUSBOTS',
                        'cols' => 60,
                        'rows' => 8,
                        'desc' => $this->trans('User-Agent contenant un identifiant à bloquer', [], 'Modules.Sj4webfirewall.Admin'),
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Activer le ralentissement (sleep)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_ENABLE_SLEEP',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'active_on', 'value' => 1, 'label' => $this->l('Oui')],
                            ['id' => 'active_off', 'value' => 0, 'label' => $this->l('Non')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Durée du sleep (ms)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_SLEEP_DELAY_MS',
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Pays à bloquer (codes ISO alpha-2)', [], 'Modules.Sj4webfirewall.Admin'),
                        'name' => 'SJ4WEB_FW_COUNTRIES_BLOCKED',
                        'cols' => 60,
                        'rows' => 3,
                        'desc' => $this->trans('Ex : RU, CN, IR', [], 'Modules.Sj4webfirewall.Admin'),
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


        $link = $this->context->link->getAdminLink('AdminSj4webFirewallLog');

        $html = '<div style="margin-bottom:15px;">';
        $html .= '<a href="' . $link . '" class="btn btn-default" target="_blank">';
        $html .= '<i class="icon icon-eye"></i> ';
        $html .= $this->trans('Consulter les IP bloquées / scorées', [], 'Modules.Sj4webfirewall.Admin');
        $html .= '</a>';
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

        return $html . $helper->generateForm([$fields_form]);
    }

    /**
     * Traitement du formulaire de configuration
     */
    public function postProcess()
    {
        if (Tools::isSubmit('submit_sj4webfirewall')) {
            foreach (Sj4webFirewallConfigHelper::getKeys() as $key) {
                $val = Tools::getValue($key);

                if (in_array($key, Sj4webFirewallConfigHelper::getMultilineKeys(), true)) {
                    $val = array_filter(array_map('trim', explode("\n", $val)));
                    $val = json_encode($val); // important ici
                }

                Configuration::updateValue($key, $val);
            }

            $this->confirmations[] = $this->trans('Configuration enregistrée', [], 'Modules.Sj4webfirewall.Admin');
        }
    }


}
