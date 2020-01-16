---
- name: Install web server
  hosts: "{{ vhosts | default('webn4') }}"

  roles:
    - ncl.apache
    - ncl.wp-mysql
    - ncl.php7
    - ncl.wordpress
