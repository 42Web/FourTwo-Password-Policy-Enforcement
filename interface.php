<?php
define('PASS_HINT', 'Your password must be at least 8 characters containing at least one uppercase letter, one lowercase letter, one number, and one symbol.');

add_action('resetpass_form', 'fourtwo_password_reset_form');
add_action('show_user_profile', 'fourtwo_password_reset_form');
add_action('edit_user_profile', 'fourtwo_password_reset_form');
function bodas_password_reset_form() {
    //wp_deregister_script('password-strength-meter');
?>
<script type="text/javascript">
jQuery(document).ready(function() {
    jQuery('.indicator-hint').html('<?php echo  PASS_HINT; ?>');
});
</script>
    
<?php
}