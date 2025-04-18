<?php
require_once dirname(__FILE__, 3) . '/config/default_config.php';
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

        parent::__construct();
    }

    /**
     * Affiche le formulaire de configuration du module dans le BO.
     */
    public function renderForm()
    {
        $fields_form = [
            'form' => [
                'legend' => [
                    'title' => $this->l('Configuration du pare-feu'),
                ],
                'input' => [
                    [
                        'type' => 'textarea',
                        'label' => $this->l('IP autorisées (whitelist)'),
                        'name' => 'SJ4WEB_FW_WHITELIST_IPS',
                        'cols' => 60,
                        'rows' => 5,
                        'desc' => $this->l('Une IP ou un range CIDR par ligne'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->l('Bots autorisés (safeBots)'),
                        'name' => 'SJ4WEB_FW_SAFEBOTS',
                        'cols' => 60,
                        'rows' => 5,
                        'desc' => $this->l('User-Agent contenant un identifiant autorisé'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->l('Bots bloqués (maliciousBots)'),
                        'name' => 'SJ4WEB_FW_MALICIOUSBOTS',
                        'cols' => 60,
                        'rows' => 8,
                        'desc' => $this->l('User-Agent contenant un identifiant à bloquer'),
                    ],
                    [
                        'type' => 'switch',
                        'label' => $this->l('Activer le ralentissement (sleep)'),
                        'name' => 'SJ4WEB_FW_ENABLE_SLEEP',
                        'is_bool' => true,
                        'values' => [
                            ['id' => 'active_on', 'value' => 1, 'label' => $this->l('Oui')],
                            ['id' => 'active_off', 'value' => 0, 'label' => $this->l('Non')],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->l('Durée du sleep (ms)'),
                        'name' => 'SJ4WEB_FW_SLEEP_DELAY_MS',
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->l('Pays à bloquer (codes ISO alpha-2)'),
                        'name' => 'SJ4WEB_FW_COUNTRIES_BLOCKED',
                        'cols' => 60,
                        'rows' => 3,
                        'desc' => $this->l('Ex : RU, CN, IR'),
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Enregistrer'),
                ],
            ],
        ];

        $values = [];
        foreach (array_keys(require dirname(__FILE__, 4) . '/config/default_config.php') as $key) {
            $val = Configuration::get($key);
            $values[$key] = is_array($val) ? implode("\n", $val) : $val;
        }

        $helper = new HelperForm();
        $helper->module = $this->module;
        $helper->name_controller = 'sj4webfirewall';
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->currentIndex = AdminController::$currentIndex . '&configure=' . $this->module->name;
        $helper->default_form_language = (int)Configuration::get('PS_LANG_DEFAULT');
        $helper->allow_employee_form_lang = Configuration::get('PS_BO_ALLOW_EMPLOYEE_FORM_LANG') ?: 0;
        $helper->title = $this->displayName;
        $helper->submit_action = 'submit_sj4webfirewall';
        $helper->fields_value = $values;

        return $helper->generateForm([$fields_form]);
    }

    /**
     * Traitement du formulaire de configuration
     */
    public function postProcess()
    {
        if (Tools::isSubmit('submit_sj4webfirewall')) {
            foreach (array_keys(require dirname(__FILE__, 4) . '/config/default_config.php') as $key) {
                $val = Tools::getValue($key);
                if (is_string($val) && strpos($val, "\n") !== false) {
                    $val = array_filter(array_map('trim', explode("\n", $val)));
                }
                Configuration::updateValue($key, $val);
            }
            $this->confirmations[] = $this->l('Configuration enregistrée');
        }
    }
}
