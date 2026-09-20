<?php

class groupOfNames extends baseModule {

    public function __construct($scope) {
        parent::__construct($scope);
        $this->autoAddObjectClasses = false;
    }

    public function can_manage() {
        return $this->get_scope() === 'group';
    }

    public function get_metaData() {
        return [
            'alias' => _('Access group'),
            'attributes' => ['cn', 'description', 'member'],
            'dependencies' => ['depends' => [], 'conflicts' => []],
            'icon' => 'group.svg',
            'ldap_filter' => ['or' => '(objectClass=groupOfNames)'],
            'objectClasses' => ['groupOfNames'],
            'RDN' => ['cn' => 'normal'],
        ];
    }

    public function display_html_attributes() {
        $return = new htmlResponsiveRow();
        if (!in_array('groupOfNames', $this->attributes['objectClass'] ?? [])) {
            $return->add(new htmlButton(
                'addGroupOfNamesExtension',
                _('Add access group extension')
            ));
            return $return;
        }

        $this->addSimpleInputTextField($return, 'cn', _('Group name'), true);
        $this->addSimpleInputTextField($return, 'description', _('Description'));
        $return->add(new htmlResponsiveInputTextarea(
            'groupOfNames_members',
            implode("\n", $this->attributes['member'] ?? []),
            70,
            8,
            _('Members'),
            'members'
        ), 12);
        $removeButton = new htmlButton(
            'removeGroupOfNamesExtension',
            _('Remove access group extension')
        );
        $removeButton->setCSSClasses(['lam-danger']);
        $return->add($removeButton, 12, 12, 12, 'text-center');
        return $return;
    }

    public function process_attributes() {
        $errors = [];
        if (isset($_POST['addGroupOfNamesExtension'])) {
            $this->attributes['objectClass'][] = 'groupOfNames';
            return $errors;
        }
        if (isset($_POST['removeGroupOfNamesExtension'])) {
            $this->attributes['objectClass'] = array_delete(
                ['groupOfNames'],
                $this->attributes['objectClass']
            );
            unset($this->attributes['member']);
            return $errors;
        }
        if (!in_array('groupOfNames', $this->attributes['objectClass'] ?? [])) {
            return $errors;
        }

        $this->attributes['cn'] = [trim($_POST['cn'] ?? '')];
        $this->attributes['description'] = [trim($_POST['description'] ?? '')];
        if ($this->attributes['description'][0] === '') {
            unset($this->attributes['description']);
        }

        $members = preg_split('/\R/', $_POST['groupOfNames_members'] ?? '');
        $members = array_values(array_unique(array_filter(array_map('trim', $members))));
        if ($members === []) {
            $errors[] = ['ERROR', _('Members'), _('A groupOfNames requires at least one member DN.')];
        }
        else {
            $this->attributes['member'] = $members;
        }
        return $errors;
    }

    public function module_complete() {
        if (!in_array('groupOfNames', $this->attributes['objectClass'] ?? [])) {
            return true;
        }
        return !empty($this->attributes['cn'][0]) && !empty($this->attributes['member']);
    }

    public function save_attributes() {
        if (!in_array('groupOfNames', $this->attributes['objectClass'] ?? [])
            && !in_array('groupOfNames', $this->orig['objectClass'] ?? [])) {
            return [];
        }
        return $this->getAccountContainer()->save_module_attributes(
            $this->attributes,
            $this->orig
        );
    }
}
