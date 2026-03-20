<?php

require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStatsLogger.php';

class AdminSj4webFirewallStatsController extends ModuleAdminController
{
    protected const LIST_ID = 'firewall_stats';

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
            'content' => $this->renderToolbar($availableDates, $selectedDate)
                . $this->renderSummary($stats)
                . $this->renderStatsList($stats, $selectedDate),
        ]);
    }

    public function postProcess()
    {
        parent::postProcess();

        if (Tools::isSubmit('submitReset' . self::LIST_ID)) {
            foreach (array_keys($_GET) as $key) {
                if (strpos($key, self::LIST_ID . 'Filter_') === 0 || strpos($key, $this->getListFilterPrefix() . self::LIST_ID . 'Filter_') === 0) {
                    unset($_GET[$key]);
                }
            }

            foreach (array_keys($_POST) as $key) {
                if (strpos($key, self::LIST_ID . 'Filter_') === 0 || strpos($key, $this->getListFilterPrefix() . self::LIST_ID . 'Filter_') === 0) {
                    unset($_POST[$key]);
                }
            }
        }
    }

    public function initPageHeaderToolbar()
    {
        parent::initPageHeaderToolbar();

        $title = $this->trans('Logs journaliers', [], 'Modules.Sj4webfirewall.Admin');
        $this->toolbar_title = $title;
        $this->page_header_toolbar_title = $title;
        $this->meta_title = $title;
    }

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
                <h3><i class="icon-bar-chart"></i> ' . $this->trans('Daily tracking logs', [], 'Modules.Sj4webfirewall.Admin') . '</h3>
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
                        <i class="icon-search"></i> ' . $this->trans('Display', [], 'Modules.Sj4webfirewall.Admin') . '
                    </button>
                </form>
            </div>';
    }

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
            [
                'label' => $this->trans('Tracked IPs', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['ips'],
                'quick_filter' => '',
            ],
            [
                'label' => $this->trans('Total hits', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['hits'],
                'quick_filter' => 'has_hits',
            ],
            [
                'label' => $this->trans('404 hits', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['error_404'],
                'quick_filter' => 'has_404',
            ],
            [
                'label' => $this->trans('403 hits', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['error_403'],
                'quick_filter' => 'has_403',
            ],
            [
                'label' => $this->trans('Safe bots', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['safe'],
                'quick_filter' => 'bot_safe',
            ],
            [
                'label' => $this->trans('Suspicious bots', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['malicious'],
                'quick_filter' => 'bot_malicious',
            ],
            [
                'label' => $this->trans('Blocked IPs', [], 'Modules.Sj4webfirewall.Admin'),
                'value' => $summary['blocked'],
                'quick_filter' => 'blocked',
            ],
        ];

        $html = '<div class="panel"><div class="row">';
        foreach ($items as $item) {
            $link = $this->buildQuickFilterLink($stats['date'], $item['quick_filter']);
            $html .= '
                <div class="col-lg-2 col-md-3 col-sm-4 col-xs-6">
                    <a href="' . htmlspecialchars($link, ENT_QUOTES, 'UTF-8') . '" class="well text-center" style="display:block; color:inherit; text-decoration:none;">
                        <strong style="display:block; font-size:20px;">' . (int) $item['value'] . '</strong>
                        <span>' . htmlspecialchars($item['label'], ENT_QUOTES, 'UTF-8') . '</span>
                    </a>
                </div>';
        }

        return $html . '</div></div>';
    }

    protected function renderStatsList($stats, $selectedDate)
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

        $limit = $this->getPaginationLimit();
        $rows = $this->applyFilters($rows);
        $rows = $this->sortEntries($rows);

        $total = count($rows);
        $page = $this->getCurrentPage($total, $limit);
        $offset = ($page - 1) * $limit;
        $rows = array_slice($rows, $offset, $limit);

        $helper = new HelperList();
        $helper->module = $this->module;
        $helper->shopLinkType = '';
        $helper->simple_header = false;
        $helper->identifier = 'ip';
        $helper->title = $this->trans('Traffic by IP', [], 'Modules.Sj4webfirewall.Admin');
        $helper->table = self::LIST_ID;
        $helper->list_id = self::LIST_ID;
        $helper->token = Tools::getAdminTokenLite('AdminSj4webFirewallStats');
        $helper->currentIndex = $this->buildStatsListIndex($selectedDate);
        $helper->show_toolbar = true;
        $helper->listTotal = $total;
        $helper->_default_pagination = 50;
        $helper->_pagination = [20, 50, 100, 300];
        $helper->tpl_vars['show_toolbar'] = true;
        $helper->tpl_vars['show_pagination'] = true;

        $fieldsList = [
            'ip' => [
                'title' => $this->trans('IP Address', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'filter_key' => 'ip',
            ],
            'type' => [
                'title' => $this->trans('Type', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'select',
                'list' => [
                    'human' => $this->trans('Human', [], 'Modules.Sj4webfirewall.Admin'),
                    'bot_safe' => $this->trans('Safe bot', [], 'Modules.Sj4webfirewall.Admin'),
                    'bot_malicious' => $this->trans('Suspicious bot', [], 'Modules.Sj4webfirewall.Admin'),
                    'blocked' => $this->trans('Blocked', [], 'Modules.Sj4webfirewall.Admin'),
                ],
                'callback' => 'formatType',
                'callback_object' => $this,
                'filter_key' => 'type',
            ],
            'bot_name' => [
                'title' => $this->trans('Bot', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'filter_key' => 'bot_name',
            ],
            'country' => [
                'title' => $this->trans('Country', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
                'filter_key' => 'country',
            ],
            'access_count' => [
                'title' => $this->trans('Hits', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
                'filter_key' => 'access_count',
            ],
            'error_404_count' => [
                'title' => $this->trans('404', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
                'filter_key' => 'error_404_count',
            ],
            'error_403_count' => [
                'title' => $this->trans('403', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
                'filter_key' => 'error_403_count',
            ],
            'score' => [
                'title' => $this->trans('Score', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
                'filter_key' => 'score',
            ],
            'first_seen' => [
                'title' => $this->trans('First Seen', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
                'filter_key' => 'first_seen',
            ],
            'last_seen' => [
                'title' => $this->trans('Last Seen', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
                'filter_key' => 'last_seen',
            ],
            'user_agent' => [
                'title' => $this->trans('User-Agent', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'filter_key' => 'user_agent',
            ],
        ];

        return '<div class="panel">' . $helper->generateList($rows, $fieldsList) . '</div>';
    }

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

    protected function applyFilters(array $rows)
    {
        $textFields = ['ip', 'bot_name', 'country', 'user_agent'];
        foreach ($textFields as $field) {
            $filter = trim((string) $this->getListFilterValue($field, ''));
            if ($filter === '') {
                continue;
            }

            $rows = array_filter($rows, function ($row) use ($field, $filter) {
                return stripos((string) ($row[$field] ?? ''), $filter) !== false;
            });
        }

        $typeFilter = trim((string) $this->getListFilterValue('type', ''));
        if ($typeFilter !== '') {
            $rows = array_filter($rows, function ($row) use ($typeFilter) {
                return strtolower((string) ($row['type'] ?? '')) === strtolower($typeFilter);
            });
        }

        $quickFilter = (string) Tools::getValue('stats_quick_filter', '');
        if ($quickFilter !== '') {
            $rows = $this->applyQuickFilter($rows, $quickFilter);
        }

        $numericFields = ['access_count', 'error_404_count', 'error_403_count', 'score'];
        foreach ($numericFields as $field) {
            $filter = trim((string) $this->getListFilterValue($field, ''));
            if ($filter === '') {
                continue;
            }

            $rows = array_filter($rows, function ($row) use ($field, $filter) {
                return $this->matchesNumericFilter((int) ($row[$field] ?? 0), $filter);
            });
        }

        $rows = $this->applyDateRangeFilter($rows, 'first_seen');
        $rows = $this->applyDateRangeFilter($rows, 'last_seen');

        return array_values($rows);
    }

    protected function applyDateRangeFilter(array $rows, $field)
    {
        $range = $this->getListFilterValue($field, []);
        $from = '';
        $to = '';

        if (is_array($range) && count($range) > 0) {
            $from = (string) ($range[0] ?? '');
            $to = (string) ($range[1] ?? '');
        }

        if ($from === '' && $to === '') {
            return $rows;
        }

        return array_values(array_filter($rows, function ($row) use ($field, $from, $to) {
            $timestamp = strtotime((string) ($row[$field] ?? ''));
            if ($timestamp === false) {
                return false;
            }

            $day = strtotime(date('Y-m-d', $timestamp));
            if ($from !== '' && $day < strtotime($from)) {
                return false;
            }

            if ($to !== '' && $day > strtotime($to)) {
                return false;
            }

            return true;
        }));
    }

    protected function sortEntries(array $rows)
    {
        $orderby = $this->getListOrderBy();
        $orderway = $this->getListOrderWay();

        if (!$orderby || empty($rows) || !array_key_exists($orderby, $rows[0])) {
            return $rows;
        }

        usort($rows, function ($a, $b) use ($orderby, $orderway) {
            $valueA = $a[$orderby];
            $valueB = $b[$orderby];

            if (
                preg_match('/^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$/', (string) $valueA) &&
                preg_match('/^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$/', (string) $valueB)
            ) {
                $valueA = strtotime((string) $valueA);
                $valueB = strtotime((string) $valueB);
            }

            if (is_numeric($valueA) && is_numeric($valueB)) {
                $comparison = $valueA <=> $valueB;
            } else {
                $comparison = strcmp((string) $valueA, (string) $valueB);
            }

            return $orderway === SORT_DESC ? -$comparison : $comparison;
        });

        return $rows;
    }

    protected function getListFilterValue($key, $default = '')
    {
        $prefixedKey = $this->getListFilterPrefix() . self::LIST_ID . 'Filter_' . $key;
        $legacyKey = self::LIST_ID . 'Filter_' . $key;

        $value = Tools::getValue($prefixedKey, null);
        if ($value === null) {
            $value = Tools::getValue($legacyKey, $default);
        }

        if (($value === null || $value === '' || $value === []) && isset($this->context->cookie->{$prefixedKey})) {
            $value = $this->context->cookie->{$prefixedKey};
        } elseif (($value === null || $value === '' || $value === []) && isset($this->context->cookie->{$legacyKey})) {
            $value = $this->context->cookie->{$legacyKey};
        }

        if (is_string($value) && ($key === 'first_seen' || $key === 'last_seen')) {
            $decoded = json_decode($value, true);
            if (is_array($decoded)) {
                $value = $decoded;
            }
        }

        return $value;
    }

    protected function getCurrentPage($totalRows, $limit)
    {
        $page = max(1, (int) Tools::getValue('submitFilter' . self::LIST_ID, 1));
        $totalPages = max(1, (int) ceil($totalRows / max(1, $limit)));

        return min($page, $totalPages);
    }

    protected function getPaginationLimit()
    {
        $limit = (int) Tools::getValue(
            self::LIST_ID . '_pagination',
            isset($this->context->cookie->{self::LIST_ID . '_pagination'})
                ? $this->context->cookie->{self::LIST_ID . '_pagination'}
                : 50
        );

        if (!in_array($limit, [20, 50, 100, 300], true)) {
            $limit = 50;
        }

        return $limit;
    }

    protected function getListFilterPrefix()
    {
        return Tools::strtolower(str_replace(['admin', 'controller'], '', $this->controller_name));
    }

    protected function getListOrderBy()
    {
        $orderBy = (string) Tools::getValue(self::LIST_ID . 'Orderby', '');
        if ($orderBy !== '') {
            return $orderBy;
        }

        $cookieKey = $this->getListFilterPrefix() . self::LIST_ID . 'Orderby';

        return isset($this->context->cookie->{$cookieKey}) ? (string) $this->context->cookie->{$cookieKey} : '';
    }

    protected function getListOrderWay()
    {
        $orderWay = strtolower((string) Tools::getValue(self::LIST_ID . 'Orderway', ''));
        if ($orderWay !== '') {
            return $orderWay === 'desc' ? SORT_DESC : SORT_ASC;
        }

        $cookieKey = $this->getListFilterPrefix() . self::LIST_ID . 'Orderway';
        $cookieValue = isset($this->context->cookie->{$cookieKey})
            ? strtolower((string) $this->context->cookie->{$cookieKey})
            : '';

        return $cookieValue === 'desc' ? SORT_DESC : SORT_ASC;
    }

    protected function applyQuickFilter(array $rows, $quickFilter)
    {
        switch ($quickFilter) {
            case 'has_hits':
                return array_values(array_filter($rows, function ($row) {
                    return (int) ($row['access_count'] ?? 0) > 0;
                }));
            case 'has_404':
                return array_values(array_filter($rows, function ($row) {
                    return (int) ($row['error_404_count'] ?? 0) > 0;
                }));
            case 'has_403':
                return array_values(array_filter($rows, function ($row) {
                    return (int) ($row['error_403_count'] ?? 0) > 0;
                }));
            case 'bot_safe':
            case 'bot_malicious':
            case 'blocked':
                return array_values(array_filter($rows, function ($row) use ($quickFilter) {
                    return (string) ($row['type'] ?? '') === $quickFilter;
                }));
            default:
                return $rows;
        }
    }

    protected function matchesNumericFilter($value, $filter)
    {
        $filter = trim((string) $filter);
        if ($filter === '') {
            return true;
        }

        if (preg_match('/^\s*(-?\d+)\s*-\s*(-?\d+)\s*$/', $filter, $matches)) {
            $min = (int) $matches[1];
            $max = (int) $matches[2];

            return $value >= min($min, $max) && $value <= max($min, $max);
        }

        if (preg_match('/^(>=|<=|>|<)\s*(-?\d+)$/', $filter, $matches)) {
            $operator = $matches[1];
            $target = (int) $matches[2];

            switch ($operator) {
                case '>=':
                    return $value >= $target;
                case '<=':
                    return $value <= $target;
                case '>':
                    return $value > $target;
                case '<':
                    return $value < $target;
            }
        }

        return is_numeric($filter) ? $value === (int) $filter : false;
    }

    protected function buildQuickFilterLink($selectedDate, $quickFilter)
    {
        $params = [
            'stats_date' => (string) $selectedDate,
        ];

        if ($quickFilter !== '') {
            $params['stats_quick_filter'] = $quickFilter;
        }

        return $this->context->link->getAdminLink('AdminSj4webFirewallStats', true, [], $params);
    }

    protected function buildStatsListIndex($selectedDate)
    {
        $params = [
            'stats_date' => (string) $selectedDate,
        ];

        $quickFilter = (string) Tools::getValue('stats_quick_filter', '');
        if ($quickFilter !== '') {
            $params['stats_quick_filter'] = $quickFilter;
        }

        return $this->context->link->getAdminLink('AdminSj4webFirewallStats', false, [], $params);
    }
}
