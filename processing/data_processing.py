# backend/processing/data_processing.py
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Set backend before importing pyplot
import matplotlib.pyplot as plt
import os

# Constants from your original code
ALPHA = -0.00130936216
BETA = -0.000000000284
GAMMA = -190.9179442
DELTA = -0.0000231
THRESHOLD_R1 = 140000
THRESHOLD_R2 = 1010000000
MEAN_R1 = 575000
STD_R1 = 4680000
MEAN_R2 = 299000000
STD_R2 = 1710000000

def clean_dataframe(df):
    """Clean in-memory DataFrame."""
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df

def clean_dataframe_in_chunks(df, chunk_size):
    """Clean DataFrame in chunks."""
    cleaned_chunks = []
    total_rows = len(df)

    for start in range(0, total_rows, chunk_size):
        end = start + chunk_size
        chunk = df.iloc[start:end].copy()
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)
        cleaned_chunks.append(chunk)

    cleaned_df = pd.concat(cleaned_chunks, ignore_index=True)
    print(f"✅ Cleaned {len(cleaned_df)} rows out of {total_rows}")
    return cleaned_df

def sort_by_timestamp(df):
    """Sort DataFrame by 'Timestamp' column."""
    if 'Timestamp' not in df.columns:
        raise ValueError("❌ 'Timestamp' column not found.")

    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.dropna(subset=['Timestamp'])
    df = df.sort_values(by='Timestamp', ascending=True).reset_index(drop=True)
    return df

def group_by_timestamp_and_assign_seconds_df(input_df):
    """Group and process timestamp data."""
    try:
        df = input_df.copy()
        df.columns = df.columns.str.strip()
        
        # Print initial dataframe info
        print(f"Initial DataFrame columns: {df.columns.tolist()}")
        print(f"DataFrame shape: {df.shape}")
        
        # Map different possible column names to standard names
        column_mappings = {
            "Timestamp": "timestamp",
            "timestamp": "timestamp",
            "time_bin": "timestamp",
            "Flow Packets/s": "flow_packets_s",
            "flow_packets_s": "flow_packets_s", 
            "flow_packets_per_sec": "flow_packets_s",
            "Flow_packets_per_sec": "flow_packets_s",
            "Flow Bytes/s": "flow_bytes_s",
            "flow_bytes_s": "flow_bytes_s",
            "flow_bytes_per_sec": "flow_bytes_s",
            "Flow_bytes_per_sec": "flow_bytes_s",
            "Label": "label",
            "label": "label"
        }
        
        # Create a mapping of actual column names to standardized names
        rename_dict = {}
        for std_name, internal_name in column_mappings.items():
            if std_name in df.columns:
                rename_dict[std_name] = internal_name
        
        # Rename columns to standardized names
        if rename_dict:
            df.rename(columns=rename_dict, inplace=True)
            print(f"After rename, columns: {df.columns.tolist()}")
        else:
            print("No column renaming needed")
        
        # Check for required columns and print helpful error messages
        required_cols = {'timestamp', 'label', 'flow_packets_s', 'flow_bytes_s'}
        missing_cols = required_cols - set(df.columns)
        
        if missing_cols:
            print(f"❌ ERROR: Missing required columns: {missing_cols}")
            print(f"Available columns: {df.columns.tolist()}")
            
            # Try to fix common issues
            if 'timestamp' not in df.columns and 'Timestamp' in df.columns:
                df.rename(columns={'Timestamp': 'timestamp'}, inplace=True)
                print("Fixed: Renamed 'Timestamp' to 'timestamp'")
            
            if 'label' not in df.columns and 'Label' in df.columns:
                df.rename(columns={'Label': 'label'}, inplace=True)
                print("Fixed: Renamed 'Label' to 'label'")
            
            # For packet data, map flow fields if missing but other versions exist
            if 'flow_packets_s' not in df.columns:
                # Try all possible variations
                packet_cols = ['flow_packets_per_sec', 'Flow_packets_per_sec', 'Flow Packets/s']
                for col in packet_cols:
                    if col in df.columns:
                        df.rename(columns={col: 'flow_packets_s'}, inplace=True)
                        print(f"Fixed: Renamed '{col}' to 'flow_packets_s'")
                        break
            
            if 'flow_bytes_s' not in df.columns:
                # Try all possible variations
                bytes_cols = ['flow_bytes_per_sec', 'Flow_bytes_per_sec', 'Flow Bytes/s']
                for col in bytes_cols:
                    if col in df.columns:
                        df.rename(columns={col: 'flow_bytes_s'}, inplace=True)
                        print(f"Fixed: Renamed '{col}' to 'flow_bytes_s'")
                        break
            
            # Check if fix worked
            missing_cols = required_cols - set(df.columns)
            if missing_cols:
                print(f"❌ ERROR: Still missing required columns after fixes: {missing_cols}")
                print(f"Final available columns: {df.columns.tolist()}")
                print("Sample data rows:")
                print(df.head(2))
                return pd.DataFrame()
        
        # Convert timestamp to datetime
        print("Converting timestamp to datetime...")
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        # Drop rows with invalid timestamps
        df = df.dropna(subset=['timestamp'])
        print(f"Valid timestamps: {len(df)} rows")
        
        if len(df) == 0:
            print("❌ ERROR: No valid timestamp data after conversion")
            return pd.DataFrame()
        
        # Group by time and label
        print("Grouping by time bin and label...")
        df['time_bin'] = df['timestamp'].dt.floor('S')
        
        grouped = df.groupby(['time_bin', 'label']).agg({
            'flow_packets_s': 'sum',
            'flow_bytes_s': 'sum'
        }).reset_index()
        
        # Take the max packets per time bin
        idx = grouped.groupby('time_bin')['flow_packets_s'].idxmax()
        grouped_df = grouped.loc[idx].copy()
        grouped_df.reset_index(drop=True, inplace=True)
        
        # Rename columns back to standard format
        grouped_df.rename(columns={
            'time_bin': 'Timestamp',
            'flow_packets_s': 'Flow_packets_per_sec',
            'flow_bytes_s': 'Flow_bytes_per_sec',
            "label": "Label"
        }, inplace=True)
        
        # Assign sequential seconds
        grouped_df['Timestamp'] = range(1, len(grouped_df) + 1)
        
        print(f"✅ Grouping complete. Output shape: {grouped_df.shape}")
        return grouped_df
        
    except Exception as e:
        import traceback
        print(f"❌ ERROR in group_by_timestamp_and_assign_seconds_df: {str(e)}")
        traceback.print_exc()
        return pd.DataFrame()

def process_flow_df(df):
    """Calculate flow derivatives and metrics."""
    delta_t = 1  # Assume uniform time intervals
    
    # Extract values
    p = df['Flow_packets_per_sec'].values
    b = df['Flow_bytes_per_sec'].values
    
    # First derivatives
    dp_dt = np.zeros_like(p)
    db_dt = np.zeros_like(b)
    dp_dt[1:-1] = (p[2:] - p[:-2]) / (2 * delta_t)
    db_dt[1:-1] = (b[2:] - b[:-2]) / (2 * delta_t)
    dp_dt[0] = (p[1] - p[0]) / delta_t
    db_dt[0] = (b[1] - b[0]) / delta_t
    dp_dt[-1] = (p[-1] - p[-2]) / delta_t
    db_dt[-1] = (b[-1] - b[-2]) / delta_t
    
    # Second derivatives
    d2p_dt2 = np.zeros_like(p)
    d2b_dt2 = np.zeros_like(b)
    d2p_dt2[1:-1] = (p[2:] - 2*p[1:-1] + p[:-2]) / (delta_t**2)
    d2b_dt2[1:-1] = (b[2:] - 2*b[1:-1] + b[:-2]) / (delta_t**2)
    
    d2p_dt2[0] = (dp_dt[1] - dp_dt[0]) / delta_t
    d2b_dt2[0] = (db_dt[1] - db_dt[0]) / delta_t
    d2p_dt2[-1] = (dp_dt[-1] - dp_dt[-2]) / delta_t
    d2b_dt2[-1] = (db_dt[-1] - db_dt[-2]) / delta_t
    
    # Add to DataFrame
    df['dp/dt'] = dp_dt
    df['db/dt'] = db_dt
    df['d2p/dt2'] = d2p_dt2
    df['d2b/dt2'] = d2b_dt2
    
    # Calculate R values
    df['R1'] = df['dp/dt'] - (ALPHA * df['d2b/dt2']) - (BETA * df['Flow_packets_per_sec'] * df['Flow_bytes_per_sec'])
    df['R2'] = df['db/dt'] - (GAMMA * df['d2p/dt2']) - (DELTA * df['Flow_packets_per_sec']**2)
    df['CR'] = df['R1'] + df['R2']
    
    return df

def compute_statistics_with_warning(df):
    """Calculate statistics and warning levels."""
    # Pre Label
    df['Pre Label'] = ((df['R1'] > THRESHOLD_R1) | (df['R2'] > THRESHOLD_R2)).astype(int)
    
    # Z-scores
    df['Z_Score_R1'] = (df['R1'] - MEAN_R1) / STD_R1
    df['Z_Score_R2'] = (df['R2'] - MEAN_R2) / STD_R2
    df['MAX_Z_Score'] = df[['Z_Score_R1', 'Z_Score_R2']].max(axis=1)
    
    # EWS calculation
    def calculate_ews(x):
        if x <= 0: return 0
        elif x < 1: return 1
        elif x <= 2: return 2
        elif x < 3: return 3
        else: return 4
    
    df['EWS'] = df['MAX_Z_Score'].apply(calculate_ews)
    return df

# ----------------------
# Plotting Functions
# ----------------------

def plot_early_warnings(df, dataset_name, output_dir):
    """Plot early warnings overlay."""
    plt.figure(figsize=(12, 6))
    
    plt.plot(df['Seconds'], df['Flow Packets/s'], color='gray', linewidth=1, label="Traffic Flow")
    
    # Convert labels to numeric codes
    scatter = plt.scatter(df['Seconds'], df['Flow Packets/s'],
                        c=df['Label'].astype('category').cat.codes, 
                        cmap='tab10', s=2, label="Classes")
    
    plt.colorbar(scatter, ticks=np.arange(len(df['Label'].astype('category').cat.categories)))
    
    warning_indices = np.where(df['EWS'] > 0)[0]
    plt.scatter(df['Seconds'].iloc[warning_indices[::10]], 
                df['Flow Packets/s'].iloc[warning_indices[::10]],
                color='red', label='Early Warning (1 per 10)', zorder=5)
    
    plt.title(f'Flow Packets/s vs Seconds with Early Warnings ({dataset_name})')
    plt.xlabel('Seconds')
    plt.ylabel('Flow Packets/s')
    plt.legend()
    plt.tight_layout()
    
    plt.savefig(output_dir)
    plt.close()
    return output_dir

# Add similar modifications to all other plotting functions following the same pattern

def plot_ews_confusion_matrix(df, dataset_name, output_dir):
    """Plot confusion matrix for EWS."""
    from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
    
    y_true = (df['Label'] != 'BENIGN').astype(int)
    y_pred = (df['EWS'] > 0).astype(int)
    
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'Attack'])
    
    plt.figure(figsize=(6, 5))
    disp.plot(cmap="Oranges", values_format='d')
    plt.title(f"EWS vs Actual Confusion Matrix ({dataset_name})")
    plt.tight_layout()
    
    plt.savefig(output_dir)
    plt.close()
    return output_dir

# ... [Add all other plotting functions with similar modifications] ...

def plot_benign_attack(df, dataset_name,output_dir):
    plt.figure(figsize=(12, 5))
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']
    plt.plot(benign['Seconds'], benign['Flow Packets/s'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['Flow Packets/s'], color='red', label='Attack')
    plt.title(f'{dataset_name} - Benign vs Attack')
    plt.xlabel("Seconds")
    plt.ylabel("Flow Packets/s")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir

def plot_test_peak_region(df, dataset_name, output_path, first_attack_index):
    plt.figure(figsize=(12, 5))
    
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']
    
    plt.plot(benign['Seconds'], benign['Flow Packets/s'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['Flow Packets/s'], color='red', label='Attack')
    
    if first_attack_index != -1 and not attack.empty:
        peak_idx = attack['Flow Packets/s'].idxmax()
        peak_time = df.loc[peak_idx, 'Seconds']
        attack_time = df.loc[first_attack_index, 'Seconds']
        
        plt.axvline(x=attack_time, color='purple', linestyle='--', label='Attack Start')
        plt.axvline(x=peak_time, color='blue', linestyle='--', label='Peak Point')
        
        plt.scatter(peak_time, 0, color='black', marker='x', s=100, zorder=5)
        plt.text(peak_time, 0.5, f'{peak_time:.1f}s', 
                ha='center', va='bottom', fontsize=9, color='black')

    plt.title("Test Data with Peak Region and Attack Start")
    plt.xlabel("Seconds")
    plt.ylabel("Flow Packets/s")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    return output_path

def plot_Flow_Packets_s(df, dataset_name, output_dir):
    plt.figure(figsize=(12, 5))
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']
    plt.plot(benign['Seconds'], benign['Flow Packets/s'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['Flow Packets/s'], color='red', label='Attack')
    plt.title(f"T(t) - Flow Packets/s vs Seconds ({dataset_name})")
    plt.xlabel("Seconds")
    plt.ylabel("T(t) = Flow Packets/s")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir


def plot_BytesPackets_s(df, dataset_name, output_dir):
    plt.figure(figsize=(12, 5))
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']

    plt.plot(benign['Seconds'], benign['Flow Bytes/s'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['Flow Bytes/s'], color='red', label='Attack')
    plt.title("Flow Bytes/s vs Seconds")
    plt.xlabel("Seconds")
    plt.ylabel("Flow Bytes/s")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir


def plot_dp_dt(df, dataset_name, output_dir):
    plt.figure(figsize=(12, 5))
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']

    plt.plot(benign['Seconds'], benign['dp/dt'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['dp/dt'], color='red', label='Attack')
    plt.title("dp/dt vs Seconds ")
    plt.xlabel("Seconds")
    plt.ylabel("dp/dt")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir
def plot_db_dt(df, dataset_name, output_dir):
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']
    
    plt.figure(figsize=(12, 5))
    plt.plot(benign['Seconds'], benign['db/dt'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['db/dt'], color='red', label='Attack')
    plt.title("db/dt vs Seconds")
    plt.xlabel("Seconds")
    plt.ylabel("db/dt")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir
def plot_d2p_dt2(df, dataset_name, output_dir):
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']
    
    plt.figure(figsize=(12, 5))
    plt.plot(benign['Seconds'], benign['d2p/dt2'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['d2p/dt2'], color='red', label='Attack')
    plt.title("d^2p/dt^2 vs Seconds ")
    plt.xlabel("Seconds")
    plt.ylabel("d^2p/dt^2")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir
def plot_d2b_dt2(df, dataset_name, output_dir):
    benign = df[df['Label'] == 'BENIGN']
    attack = df[df['Label'] != 'BENIGN']
    
    plt.figure(figsize=(12, 5))
    plt.plot(benign['Seconds'], benign['d2b/dt2'], color='green', label='Benign')
    plt.plot(attack['Seconds'], attack['d2b/dt2'], color='red', label='Attack')
    plt.title("d^2b/dt^2 vs Seconds ")
    plt.xlabel("Seconds")
    plt.ylabel("d^2b/dt^2")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir

def plot_alert_levels_separately(df, dataset_name, output_dir):
    level_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Very High'}
    colors = {1: 'green', 2: 'orange', 3: 'red', 4: 'purple'}
    
    # Identify attack start and stop using label column
    attack_indices = df[df['Label'] != 'BENIGN'].index
    attack_present = not attack_indices.empty
    filenames = []
    
    if attack_present:
        start_attack = df.loc[attack_indices[0], 'Seconds']
        stop_attack = df.loc[attack_indices[-1], 'Seconds']

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Loop through each alert level and generate separate plots
    for level in [1, 2, 3, 4]:
        alert_df = df[df['EWS'] == level]
        total = len(alert_df)
        
        if alert_df.empty:
            print(f"No data found for {level_map[level]} level alerts.")
            continue

        # Create new figure for each plot
        plt.figure(figsize=(12, 6))

        # Plot base traffic flow
        plt.plot(df['Seconds'], df['Flow Packets/s'], 
                color='gray', linewidth=1, label='Traffic Flow')

        # Highlight current level alerts
        plt.scatter(alert_df['Seconds'], alert_df['Flow Packets/s'],
                    color=colors[level], s=20, 
                    label=f'{level_map[level]} Alert - {total}')

        # Add attack markers if present
        if attack_present:
            plt.axvline(start_attack, color='red', linestyle='--', label='Attack Start')
            plt.text(start_attack, plt.ylim()[1]*0.85,
                    f'Start\n{start_attack:.1f}s',
                    color='red', rotation=90, va='top', ha='center',
                    fontsize=9, fontweight='bold')

            plt.axvline(stop_attack, color='darkred', linestyle='--', label='Attack Stop')
            plt.text(stop_attack, plt.ylim()[1]*0.65,
                    f'Stop\n{stop_attack:.1f}s',
                    color='darkred', rotation=90, va='top', ha='center',
                    fontsize=9, fontweight='bold')

        # Configure plot
        plt.title(f"{level_map[level]} Level Alerts - Flow Packets/s")
        plt.xlabel("Time (Seconds)")
        plt.ylabel("Flow Packets/s")
        plt.legend(loc='upper right', fontsize=8)
        plt.grid(True)
        plt.tight_layout()

        # Save individual plot
        filename = f"alert_level_{level}.png"
        filepath = os.path.join(output_dir, filename)
        plt.savefig(filepath)
        plt.close()
        
        filenames.append(filename)

    return filenames
def plot_Flow_Packets_s_with_Attack_EWS(df,dataset_name, output_dir):
    
    # Convert timestamp to numeric seconds
    # df['Seconds'] = df['timestamp']
    
    # Create output directory
    # output_dir = "kurtosis_alert_plots"
    # os.makedirs(output_dir, exist_ok=True)
    
    # === Plot Setup ===
    plt.figure(figsize=(14, 6))
    
    # Plot the existing kurtosis values from CSV
    plt.plot(
        df['Seconds'],
        df['Flow Packets/s'],
        label='Flow Packets/s',
        color='blue'
    )
    # First, filter out benign traffic
    non_benign_df = df[df['Label'] != 'BENIGN']
    
    # Now find the peak in non-benign traffic
    peak_idx = non_benign_df['Flow Packets/s'].idxmax()
    peak_seconds = non_benign_df.loc[peak_idx, 'Seconds']
    peak_value = non_benign_df.loc[peak_idx, 'Flow Packets/s']
    
    
    # === Identify Attack Region Based on Label Column ===
    
    attack_indices = df[df['Label'] != 'BENIGN'].index
    if not attack_indices.empty:
        start_attack = df.loc[attack_indices[0], 'Seconds']
        stop_attack = df.loc[attack_indices[-1], 'Seconds']
    
        # Attack Start Line
        plt.axvline(x=start_attack, color='red', linestyle='--', label='Attack Start', zorder=4)
        plt.text(
            start_attack, plt.ylim()[1]*0.7,  # position text near top
            f'Start\n{start_attack:.2f}s',
            color='red', rotation=90, va='top', ha='center',
            fontsize=9, fontweight='bold'
        )
    
        # Attack Stop Line
        plt.axvline(x=stop_attack, color='darkred', linestyle='--', label='Attack Stop', zorder=4)
        plt.text(
            stop_attack, plt.ylim()[1]*0.5,
            f'Stop\n{stop_attack:.2f}s',
            color='darkred', rotation=90, va='top', ha='center',
            fontsize=9, fontweight='bold'
        )
        plt.scatter(peak_seconds, peak_value, color='purple', s=150, marker='*', label="Peak Attack", zorder=6)
        plt.text(
            peak_seconds + 10,            # Move right
            peak_value - 0.1 * peak_value,  # Slightly above the star
            f'peak_second\n{peak_seconds:.2f}s',
            color='darkred',
            va='bottom',
            ha='left',
            fontsize=9,
            fontweight='bold'
        )
    
    
    # === Mark First 3 High Alerts (EWS Level 4) ===
    high_alerts = df[df['EWS'] == 4].sort_values('Seconds')
    selected_alerts = []
    
    for _, row in high_alerts.iterrows():
        sec = row['Seconds']
        if not selected_alerts or all(abs(sec - prev['Seconds']) >= 10 for prev in selected_alerts):
            selected_alerts.append(row)
        if len(selected_alerts) == 3:
            break
    
    first_3 = pd.DataFrame(selected_alerts)
    
    ews_colors = ['green', 'orange', 'purple']
    text_offsets = [0.55, 0.70, 0.89]
    for idx, (_, row) in enumerate(first_3.iterrows()):
        sec = row['Seconds']
        flow= row['Flow Packets/s']
        color = ews_colors[idx % len(ews_colors)]
        offset = text_offsets[idx % len(text_offsets)]
    
        plt.axvline(x=sec, color=color, linestyle='-.', linewidth=2, label=f'EWS {idx+1}',zorder=6)
        plt.text(
            sec, plt.ylim()[1]*offset,
            f'EWS {idx+1}\n{sec:.2f}s',
            color=color, rotation=90, va='top', ha='center',
            fontsize=9, fontweight='bold'
        )
        plt.scatter(sec, flow, color=color, marker='x', s=100, zorder=5)
    
    # === Final Touches ===
    plt.title("Test- Flow Packets/s with Attack & EWS")
    plt.xlabel("Time (Seconds)")
    plt.ylabel("Flow Packets/s")
    plt.grid(True)
    plt.legend(loc='upper right', fontsize=6)
    
    plt.tight_layout()
    # Save and show plot
    plt.savefig(output_dir)
    plt.close()
    return output_dir

def plot_All_alerts(df,dataset_name, output_dir="output"):
# Mapping for alert levels and colors
    level_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Very High'}
    colors = {1: 'green', 2: 'orange', 3: 'red', 4: 'purple'}
    
    
    # Identify attack region using the 'label' column
    # majority_label = df['Label'].mode()[0]
    attack_indices = df[df['Label'] != 'BENIGN'].index
    
    attack_present = not attack_indices.empty
    if attack_present:
        start_attack = df.loc[attack_indices[0], 'Seconds']
        stop_attack = df.loc[attack_indices[-1], 'Seconds']
    
    # Start plotting
    plt.figure(figsize=(12, 6))
    
    # Plot base traffic flow
    plt.plot(df['Seconds'], df['Flow Packets/s'], color='gray', linewidth=1, label='Traffic Flow')
    
    # Plot EWS alerts
    for level in [1, 2, 3, 4]:
        alert_df = df[df['EWS'] == level]
        total = len(alert_df)
        print(level, total)
        
        if alert_df.empty:
            print(f"No data found for {level_map[level]} level alerts.")
            continue
    
        plt.scatter(alert_df['Seconds'], alert_df['Flow Packets/s'],
                    color=colors[level], s=20,
                    label=f'{level_map[level]} Alert - {total}')
    
    # === Attack Start & Stop Markers ===
    if attack_present:
        plt.axvline(x=start_attack, color='red', linestyle='--', label='Attack Start', zorder=4)
        plt.text(
            start_attack, plt.ylim()[1]*0.85,
            f'Start\n{start_attack}s',
            color='red', rotation=90, va='top', ha='center',
            fontsize=9, fontweight='bold'
        )
    
        plt.axvline(x=stop_attack, color='darkred', linestyle='--', label='Attack Stop', zorder=4)
        plt.text(
            stop_attack, plt.ylim()[1]*0.65,
            f'Stop\n{stop_attack}s',
            color='darkred', rotation=90, va='top', ha='center',
            fontsize=9, fontweight='bold'
        )
    
    # Final touches
    plt.title("Flow Packets per Second with EWS Alerts")
    plt.xlabel("Time (Seconds)")
    plt.ylabel("Flow Packets/s")
    plt.legend(loc='upper right', fontsize=6)
    plt.tight_layout()
    plt.savefig(output_dir)
    plt.close()
    return output_dir
def generate_emergency_alerts(df, dataset_name, output_dir):
    """Generate emergency alerts plot."""
    plt.figure(figsize=(14, 6))
    
    # Plot base traffic
    plt.plot(df['Seconds'], df['Flow Packets/s'], 
            color='blue', linewidth=1, label="Flow Packets/s")
    
    # Highlight emergency alerts
    emergency_alerts = df[df['EWS'] == 4]
    plt.scatter(emergency_alerts['Seconds'], emergency_alerts['Flow Packets/s'],
               color='red', s=100, marker='x', label="Emergency Alerts")
    
    # Add plot decorations
    plt.title(f"{dataset_name} - Emergency Alerts")
    plt.xlabel("Seconds")
    plt.ylabel("Flow Packets/s")
    plt.legend()
    plt.grid(True)
    
    plt.savefig(output_dir)
    plt.close()
    return output_dir