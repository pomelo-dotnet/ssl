Page({
    layout: '/shared/layout',
    style: true,
    mounted() {
        this.$root.active = 'request';
    },
    unmounted() {
        this.$root.active = null;
    }
});