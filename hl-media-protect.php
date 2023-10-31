<?php

/*
Plugin Name: Media Protect
Plugin URI: https://www.hayloft-it.ch
Version: 1.0
Author: Hayloft-IT GmbH
Author URI: https://www.hayloft-it.ch
Text Domain: hl-media-protect
Description: Schützt Medien vor unberechtigten Zugriffen.
*/

class HL_Media_Protect
{
    public function register()
    {
        add_filter('mod_rewrite_rules', function($rules) {
            return $this->rewrite_rules($rules);
        });

        add_filter('robots_txt', function($output) {
            return $this->rewrite_robots_txt($output);
        });

        add_action('init', function() {
            if (isset($_GET['hl_download']) && isset($_GET['attachment_id'])) {
                $this->serve($_GET['attachment_id']);
            }
        });

        add_action('after_setup_theme', function() {
            if (class_exists(ACF::class)) {
                $this->register_acf();
            }
        });

        add_action('the_post', function(WP_Post $post) {
            if ($post->post_type === 'attachment') {
                $this->filter_attachment($post);
            }
        });

        add_filter('redirect_canonical', function($redirect_url, $requested_url) {
            return $this->fix_redirect($redirect_url, $requested_url);
        }, 10, 2);

        add_filter('the_posts', function($posts, WP_Query $query) {
            return $this->filter_posts($posts, $query);
        }, 10, 2);

        add_action('edit_attachment', function() {
            $this->flush_rewrite_rules();
        }, 1000, 2);

        add_action('add_attachment', function($attachment_id) {
            $this->protect_attachment_for_parent_post($attachment_id);
            $this->flush_rewrite_rules();
        }, 1000, 2);
    }

    private function register_acf()
    {
        acf_add_local_field_group(array(
            'key' => 'group_5fd23aef8d9ee',
            'title' => 'Medien Passwort',
            'fields' => array(
                array(
                    'key' => 'field_5fd23b05c9ecd',
                    'label' => __('Sichtbarkeit'),
                    'name' => 'hl_visibility',
                    'type' => 'select',
                    'instructions' => '',
                    'required' => 0,
                    'conditional_logic' => 0,
                    'wrapper' => array(
                        'width' => '',
                        'class' => '',
                        'id' => '',
                    ),
                    'choices' => array(
                        'public' => __('Public'),
                        'private' => __('Private'),
                        'password' => __('Password protected'),
                    ),
                    'default_value' => false,
                    'allow_null' => 0,
                    'multiple' => 0,
                    'ui' => 0,
                    'return_format' => 'value',
                    'ajax' => 0,
                    'placeholder' => '',
                ),
                array(
                    'key' => 'field_5fd23b1dc9ece',
                    'label' => __('Password'),
                    'name' => 'hl_password',
                    'type' => 'text',
                    'instructions' => '',
                    'required' => 0,
                    'conditional_logic' => array(
                        array(
                            array(
                                'field' => 'field_5fd23b05c9ecd',
                                'operator' => '==',
                                'value' => 'password',
                            ),
                        ),
                    ),
                    'wrapper' => array(
                        'width' => '',
                        'class' => '',
                        'id' => '',
                    ),
                    'default_value' => '',
                    'placeholder' => '',
                    'prepend' => '',
                    'append' => '',
                    'maxlength' => '',
                ),
            ),
            'location' => array(
                array(
                    array(
                        'param' => 'attachment',
                        'operator' => '==',
                        'value' => 'all',
                    ),
                ),
            ),
            'menu_order' => 0,
            'position' => 'normal',
            'style' => 'default',
            'label_placement' => 'top',
            'instruction_placement' => 'label',
            'hide_on_screen' => '',
            'active' => true,
            'description' => '',
        ));
    }

    private function serve($attachment_id)
    {
        define('DONOTCACHEPAGE', true);
        $visibility = get_field('hl_visibility', $attachment_id);
        switch ($visibility) {
            case 'private':
                if (current_user_can('read_private_posts')) {
                    $this->download($attachment_id);
                }
                break;
            case 'password':
                $attachment = get_post($attachment_id);

                $password = get_field('hl_password', $attachment_id);
                if (!$password && $attachment->post_parent) {
                    $password = get_post($attachment->post_parent)->post_password;
                }

                $attachment->post_password = apply_filters('hl_media_protect_password', $password);

                if (current_user_can('read_private_posts') || !post_password_required($attachment)) {
                    $this->download($attachment_id);
                    break;
                }
                if (post_password_required($attachment)) {
                    remove_filter('the_content', 'prepend_attachment');
                }
                break;
            default:
                $this->download($attachment_id);
        }
    }

    private function download($attachment_id)
    {
        header('Content-type: ' . get_post_mime_type($attachment_id));
        echo file_get_contents(get_attached_file($attachment_id));
        exit;
    }

    private function rewrite_rules($rules)
    {
        $attachments = get_posts([
            'post_type' => 'attachment',
            'post_status' => null,
            'meta_key' => 'hl_visibility',
            'meta_value' => ['private', 'password'],
            'numberposts' => -1,
        ]);

        $files_rules = [];
        foreach ($attachments as $attachment) {
            $url = wp_get_attachment_url($attachment->ID);
            $local_url = explode(site_url(), $url)[1];
            $local_url = str_replace('/wp-content', 'wp-content', $local_url);

            $files_rules[] = 'RewriteRule ^' . $local_url . '$ /index.php?hl_download=1&attachment_id=' . $attachment->ID . ' [NC,L]';
        }

        $rules .= PHP_EOL . '<IfModule mod_rewrite.c>' . PHP_EOL
            . 'RewriteEngine On' . PHP_EOL
            . implode(PHP_EOL, $files_rules) . PHP_EOL
            . '</IfModule>' . PHP_EOL;

        return $rules;
    }

    private function rewrite_robots_txt($output)
    {
        $attachments = get_posts([
            'post_type' => 'attachment',
            'post_status' => null,
            'meta_key' => 'hl_visibility',
            'meta_value' => ['private', 'password'],
            'numberposts' => -1,
        ]);

        $rules = [];
        foreach ($attachments as $attachment) {
            $url = wp_get_attachment_url($attachment->ID);
            $local_url = explode(site_url(), $url)[1];

            if ($local_url) {
                $rules[] = 'Disallow: ' . $local_url;
            }
        }

        return $output . PHP_EOL . implode(PHP_EOL, $rules);
    }

    private function filter_attachment(WP_Post $post)
    {
        $attachment_id = $post->ID;
        $visibility = get_field('hl_visibility', $attachment_id);
        if ($visibility === 'password') {
            $password = get_field('hl_password', $attachment_id);
            if (!$password && $post->post_parent) {
                $password = get_post($post->post_parent)->post_password;
            }

            $post->post_password = apply_filters('hl_media_protect_password', $password);
        }
    }

    private function filter_posts($posts, WP_Query $query)
    {
        if (!count($posts) && isset($_GET['hl_download']) && isset($_GET['attachment_id'])) {
            $attachment = get_post($_GET['attachment_id']);
            if ($attachment) {
                if (get_field('hl_visibility', $attachment) === 'private'
                    && !current_user_can('read_private_posts')
                ) {
                    return $posts;
                }

                $query->is_404 = false;
                $query->is_feed = false;
                return [$attachment];
            }
        }

        return $posts;
    }

    private function fix_redirect($redirect_url, $requested_url)
    {
        if (isset($_GET['hl_download']) && isset($_GET['attachment_id'])) {
            // do not redirect
            return $requested_url;
        }

        return $redirect_url;
    }

    private function flush_rewrite_rules()
    {
        save_mod_rewrite_rules();
    }

    private function protect_attachment_for_parent_post($attachment_id)
    {
        $attachment = get_post($attachment_id);
        if ($attachment->post_parent) {
            $post = get_post($attachment->post_parent);
            if ($post && $post->post_password) {
                update_field('hl_visibility', 'password', $attachment_id);
            } elseif ($post && get_post_status($post) === 'private') {
                update_field('hl_visibility', 'private', $attachment_id);
            }
        }
    }
}

(new HL_Media_Protect())->register();
