<?php

require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStatsLogger.php';

class AdminSj4webFirewallStatsController extends ModuleAdminController
{
    public function __construct()
    {
        $this->bootstrap = true;
        $this->className = false;
        $this->table = 'sj4web_firewall_stats';
        $this->lang = false;
        $this->explicitSelect = false;
        $this->deleted = false;
        $this->display = 'list';
        $this->module = Module::getInstanceByName('sj4webfirewall');

        parent::__construct();
    }

    public function initContent()
    {
        parent::initContent();

        $availableDates = FirewallStatsLogger::listAvailableDates();
        rsort($availableDates);

        $selectedDate = (string) Tools::getValue('stats_date', '');
        if ($selectedDate === '' || !in_array($selectedDate, $availableDates, true)) {
            $selectedDate = !empty($availableDates) ? $availableDates[0] : date('Y-m-d');
        }

        $stats = FirewallStatsLogger::getStatsForDate($selectedDate);

        $this->context->smarty->assign([
            'content' => $this->renderToolbar($availableDates, $selectedDate) . $this->renderSummary($stats) . $this->renderStatsList($stats),
        ]);
    }

    /**
     * Affiche le selecteur de date du BO.
     */
    protected function renderToolbar(array $availableDates, $selectedDate)
    {
        $options = '';
        foreach ($availableDates as $date) {
            $options .= sprintf(
                '<option value="%s"%s>%s</option>',
                htmlspecialchars($date, ENT_QUOTES, 'UTF-8'),
                $date === $selectedDate ? ' selected="selected"' : '',
                htmlspecialchars($date, ENT_QUOTES, 'UTF-8')
            );
        }

        if ($options === '') {
            $options = '<option value="' . htmlspecialchars($selectedDate, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($selectedDate, ENT_QUOTES, 'UTF-8') . '</option>';
        }

        $action = htmlspecialchars($this->context->link->getAdminLink('AdminSj4webFirewallStats'), ENT_QUOTES, 'UTF-8');

        return '
            <div class="panel">
                <h3><i class="material-icons">analytics</i> ' . $this->trans('Daily tracking logs', [], 'Modules.Sj4webfirewall.Admin') . '</h3>
                <form method="get" action="' . $action . '" class="form-inline">
                    <input type="hidden" name="controller" value="AdminSj4webFirewallStats">
                    <input type="hidden" name="token" value="' . htmlspecialchars(Tools::getAdminTokenLite('AdminSj4webFirewallStats'), ENT_QUOTES, 'UTF-8') . '">
                    <div class="form-group">
                        <label for="sj4web-fw-stats-date" style="margin-right:8px;">' . $this->trans('Date', [], 'Modules.Sj4webfirewall.Admin') . '</label>
                        <select id="sj4web-fw-stats-date" class="form-control" name="stats_date" style="min-width:220px; margin-right:8px;">
                            ' . $options . '
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">
                        <i class="material-icons">search</i> ' . $this->trans('Display', [], 'Modules.Sj4webfirewall.Admin') . '
                    </button>
                </form>
            </div>';
    }

    /**
     * Affiche un resume rapide de la journee selectionnee.
     */
    protected function renderSummary($stats)
    {
        if (empty($stats['ips'])) {
            return '<div class="panel"><div class="alert alert-warning">' . $this->trans('No statistics are available for the selected date.', [], 'Modules.Sj4webfirewall.Admin') . '</div></div>';
        }

        $summary = [
            'ips' => count($stats['ips']),
            'hits' => 0,
            'error_404' => 0,
            'error_403' => 0,
            'safe' => 0,
            'malicious' => 0,
            'blocked' => 0,
        ];

        foreach ($stats['ips'] as $row) {
            $summary['hits'] += (int) $row['access_count'];
            $summary['error_404'] += (int) $row['error_404_count'];
            $summary['error_403'] += (int) $row['error_403_count'];

            if ($row['type'] === 'bot_safe') {
                ++$summary['safe'];
            } elseif ($row['type'] === 'bot_malicious') {
                ++$summary['malicious'];
            } elseif ($row['type'] === 'blocked') {
                ++$summary['blocked'];
            }
        }

        $items = [
            $this->trans('Tracked IPs', [], 'Modules.Sj4webfirewall.Admin') => $summary['ips'],
            $this->trans('Total hits', [], 'Modules.Sj4webfirewall.Admin') => $summary['hits'],
            $this->trans('404 hits', [], 'Modules.Sj4webfirewall.Admin') => $summary['error_404'],
            $this->trans('403 hits', [], 'Modules.Sj4webfirewall.Admin') => $summary['error_403'],
            $this->trans('Safe bots', [], 'Modules.Sj4webfirewall.Admin') => $summary['safe'],
            $this->trans('Suspicious bots', [], 'Modules.Sj4webfirewall.Admin') => $summary['malicious'],
            $this->trans('Blocked IPs', [], 'Modules.Sj4webfirewall.Admin') => $summary['blocked'],
        ];

        $html = '<div class="panel"><div class="row">';
        foreach ($items as $label => $value) {
            $html .= '
                <div class="col-lg-2 col-md-3 col-sm-4 col-xs-6">
                    <div class="well text-center">
                        <strong style="display:block; font-size:20px;">' . (int) $value . '</strong>
                        <span>' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</span>
                    </div>
                </div>';
        }

        return $html . '</div></div>';
    }

    /**
     * Construit la liste exploitable des IPs pour la date choisie.
     */
    protected function renderStatsList($stats)
    {
        if (empty($stats['ips'])) {
            return '';
        }

        $rows = [];
        foreach ($stats['ips'] as $ip => $row) {
            $rows[] = [
                'ip' => $ip,
                'type' => $row['type'],
                'bot_name' => $row['bot_name'] ?: '-',
                'country' => $row['country'] ?: '-',
                'access_count' => (int) $row['access_count'],
                'error_404_count' => (int) $row['error_404_count'],
                'error_403_count' => (int) $row['error_403_count'],
                'score' => (int) $row['score'],
                'first_seen' => $row['first_seen'],
                'last_seen' => $row['last_seen'],
                'user_agent' => $row['user_agent'],
            ];
        }

        $helper = new HelperList();
        $helper->module = $this->module;
        $helper->shopLinkType = '';
        $helper->simple_header = false;
        $helper->identifier = 'ip';
        $helper->title = $this->trans('Traffic by IP', [], 'Modules.Sj4webfirewall.Admin');
        $helper->table = 'sj4web_firewall_stats';
        $helper->token = Tools::getAdminTokenLite('AdminSj4webFirewallStats');
        $helper->currentIndex = AdminController::$currentIndex;
        $helper->show_toolbar = false;
        $helper->listTotal = count($rows);
        $helper->tpl_vars['show_pagination'] = false;

        $fieldsList = [
            'ip' => [
                'title' => $this->trans('IP Address', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
            ],
            'type' => [
                'title' => $this->trans('Type', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'callback' => 'formatType',
                'callback_object' => $this,
            ],
            'bot_name' => [
                'title' => $this->trans('Bot', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
            ],
            'country' => [
                'title' => $this->trans('Country', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
            ],
            'access_count' => [
                'title' => $this->trans('Hits', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
            ],
            'error_404_count' => [
                'title' => $this->trans('404', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
            ],
            'error_403_count' => [
                'title' => $this->trans('403', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
            ],
            'score' => [
                'title' => $this->trans('Score', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
            ],
            'first_seen' => [
                'title' => $this->trans('First Seen', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
            ],
            'last_seen' => [
                'title' => $this->trans('Last Seen', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
            ],
            'user_agent' => [
                'title' => $this->trans('User-Agent', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
            ],
        ];

        return '<div class="panel">' . $helper->generateList($rows, $fieldsList) . '</div>';
    }

    /**
     * Rend le type de trafic plus lisible dans le BO.
     */
    public function formatType($value)
    {
        $labels = [
            'human' => $this->trans('Human', [], 'Modules.Sj4webfirewall.Admin'),
            'bot_safe' => $this->trans('Safe bot', [], 'Modules.Sj4webfirewall.Admin'),
            'bot_malicious' => $this->trans('Suspicious bot', [], 'Modules.Sj4webfirewall.Admin'),
            'blocked' => $this->trans('Blocked', [], 'Modules.Sj4webfirewall.Admin'),
        ];

        return $labels[$value] ?? (string) $value;
    }
}
