﻿Page({
    layout: '/shared/layout',
    style: true,
    mounted() {
        this.$root.active = 'home';
    },
    unmounted() {
        this.$root.active = null;
    }
});