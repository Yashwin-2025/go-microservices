import pandas as pd

def create_other_os_assets_table(csv_file_path):
    # Define the required columns with the updated names
    required_columns = [
        'name', 'platform', 'system_type', 'agent_type', 'asset_owner',
        'visible_name', 'auth_scan_status', 'last_discovered_time',
        'logged_user_time', 'logged_in_user', 'asset_logon_user',
        'asset_logon_time', 'auto_update', 'cred_id', 'snmp_cred_id',
        'os_patches', 'os_install_date', 'os_autoupdate', 'os_vendor',
        'snmp_info', 'codename', 'ip', 'ip_extra', 'asset_type',
        'is_firewall', 'domain', 'kernel', 'unique_id', 'host_name',
        'architecture', 'cpu_core', 'discovered', 'icon', 'status',
        'hardware_model', 'importance', 'serial_number', 'mac',
        'manufacturer', 'physical_memory', 'uptime', 'asset_category',
        'last_reset_time', 'is_deprecated', 'deprecated_time',
        'discovered_protocols', 'custom_profile_id', 'tags', 'manual_tags',
        'agent_id', 'company_id', 'tenantid', 'id', 'created', 'updated',
        'discoverysettings_id', 'last_ping_time', 'scan_status', 'ad_check',
        'configuration_id', 'install_required_patches', 'full_os_build',
        'finger_print', 'is_allowed', 'is_oval', 'asset_id',
        'company_id_vulnerability', 'tenantid_vulnerability', 'is_confirmed',
        'is_suppressed', 'id_vulnerability', 'created_vulnerability',
        'updated_vulnerability', 'suppressed_till', 'is_remediated',
        'remediated_on', 'os_name'  # Added os_name to the required columns
    ]

    try:
        # Load the entire CSV file into a DataFrame
        df = pd.read_csv(csv_file_path)

        # Rename columns if needed
        df.columns = [col.replace('__1', '_vulnerability') for col in df.columns]

        # Select only the required columns
        df = df[required_columns]

        # Replace NaN values with 'placeholder'
        df.fillna('placeholder', inplace=True)

        # Save the DataFrame to a CSV file
        df.to_csv('other_os_assets.csv', index=False)
        print("DataFrame saved to 'other_os_assets.csv'.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    create_other_os_assets_table(r'other_os_vulnerabilities.csv')
