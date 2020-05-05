from PyInstaller.utils.hooks import get_package_paths

datas = [(get_package_paths('orderedmultidict')[1] + "/__version__.py", 'orderedmultidict')]
datas.extend([(HOMEPATH + '/cbapi/response/models/*', 'cbapi/response/models/'),
                     (HOMEPATH + '/cbapi/protection/models/*', 'cbapi/protection/models/'),
                     (HOMEPATH + '/cbapi/defense/models/*', 'cbapi/defense/models/') ])

a = Analysis(['scripts/cb-taxii-connector'],
             pathex=['.'],
             hiddenimports=['orderedmultidict', 'orderedmultidict.__version__', 'cabby','unicodedata', 'requests', 'cybox.objects.account_object', 'cybox.objects.address_object', 'cybox.objects.api_object', 'cybox.objects.archive_file_object', 'cybox.objects.artifact_object', 'cybox.objects.arp_cache_object', 'cybox.objects.as_object', 'cybox.objects.code_object', 'cybox.objects.custom_object', 'cybox.objects.device_object', 'cybox.objects.disk_object', 'cybox.objects.disk_partition_object', 'cybox.objects.dns_cache_object', 'cybox.objects.dns_query_object', 'cybox.objects.dns_record_object', 'cybox.objects.domain_name_object', 'cybox.objects.email_message_object', 'cybox.objects.file_object', 'cybox.objects.gui_dialogbox_object', 'cybox.objects.gui_object', 'cybox.objects.gui_window_object', 'cybox.objects.hostname_object', 'cybox.objects.http_session_object', 'cybox.objects.image_file_object', 'cybox.objects.library_object', 'cybox.objects.link_object', 'cybox.objects.linux_package_object', 'cybox.objects.memory_object', 'cybox.objects.mutex_object', 'cybox.objects.network_route_object', 'cybox.objects.network_connection_object', 'cybox.objects.network_packet_object', 'cybox.objects.network_route_entry_object', 'cybox.objects.network_socket_object', 'cybox.objects.network_subnet_object', 'cybox.objects.pdf_file_object', 'cybox.objects.pipe_object', 'cybox.objects.port_object', 'cybox.objects.process_object', 'cybox.objects.product_object', 'cybox.objects.semaphore_object', 'cybox.objects.sms_message_object', 'cybox.objects.socket_address_object', 'cybox.objects.system_object', 'cybox.objects.uri_object', 'cybox.objects.user_account_object', 'cybox.objects.volume_object', 'cybox.objects.whois_object', 'cybox.objects.win_computer_account_object', 'cybox.objects.win_critical_section_object', 'cybox.objects.win_driver_object', 'cybox.objects.win_event_log_object', 'cybox.objects.win_event_object', 'cybox.objects.win_executable_file_object', 'cybox.objects.win_file_object', 'cybox.objects.win_filemapping_object', 'cybox.objects.win_handle_object', 'cybox.objects.win_hook_object', 'cybox.objects.win_kernel_hook_object', 'cybox.objects.win_kernel_object', 'cybox.objects.win_mailslot_object', 'cybox.objects.win_memory_page_region_object', 'cybox.objects.win_mutex_object', 'cybox.objects.win_network_route_entry_object', 'cybox.objects.win_network_share_object', 'cybox.objects.win_pipe_object', 'cybox.objects.win_prefetch_object', 'cybox.objects.win_process_object', 'cybox.objects.win_registry_key_object', 'cybox.objects.win_semaphore_object', 'cybox.objects.win_service_object', 'cybox.objects.win_system_object', 'cybox.objects.win_system_restore_object', 'cybox.objects.win_task_object', 'cybox.objects.win_thread_object', 'cybox.objects.win_user_object', 'cybox.objects.win_volume_object', 'cybox.objects.win_waitable_timer_object', 'cybox.objects.x509_certificate_object'],
             datas=datas,
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='cb-taxii-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='cb-taxii-connector')
