from scapy.all import rdpcap
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

# --- File Reading ---
print("Starting to read the .pcapng file...")
packets = rdpcap("28-1-25-bro-rpi-30ms.pcapng")
print(f"Finished reading file. Total packets loaded: {len(packets)}")

# --- Compute Delays ---
print("Computing delays between successive packets...")
num_packets = len(packets)
delays = []
for i in range(1, num_packets):
    # Add a progress message every 10% of the total iterations
    if i % (num_packets // 10) == 0:
        print(f"Processed {i}/{num_packets} packets...")
    delay = packets[i].time - packets[i - 1].time
    delays.append(delay)
print("Delay computation complete.")

# --- Descriptive Statistics ---
num_intervals = len(delays)
mean_delay = np.mean(delays)
median_delay = np.median(delays)
std_delay = np.std(delays)
min_delay = np.min(delays)
max_delay = np.max(delays)

print("\nDescriptive Statistics:")
print("Total number of delay intervals:", num_intervals)
print("Mean delay: {:.6f} seconds".format(mean_delay))
print("Median delay: {:.6f} seconds".format(median_delay))
print("Standard deviation of delays: {:.6f} seconds".format(std_delay))
print("Minimum delay: {:.6f} seconds".format(min_delay))
print("Maximum delay: {:.6f} seconds".format(max_delay))

# --- Delay Classification ---
print("\nClassifying delays into categories...")
delay_categories = []
# Process each delay and classify it, printing progress every 10%
for idx, d in enumerate(delays):
    if idx % (num_intervals // 10 if num_intervals >= 10 else 1) == 0:
        print(f"Classified {idx}/{num_intervals} intervals...")
    if d < mean_delay:
        delay_categories.append("Transmission Delay")
    elif d < mean_delay + std_delay:
        delay_categories.append("Processing Delay")
    else:
        delay_categories.append("Retransmission/Anomaly Delay")
print("Delay classification complete.")

# Color mapping for visualization
color_map = {
    "Transmission Delay": "green",
    "Processing Delay": "orange",
    "Retransmission/Anomaly Delay": "red",
}

# --- Visualization ---

# # 1. Scatter Plot: Delay values with color-coding based on category
# print("Generating scatter plot for delay classification...")
# plt.figure(figsize=(12, 6))
# for idx, (d, category) in enumerate(zip(delays, delay_categories)):
#     plt.scatter(
#         idx,
#         d,
#         color=color_map[category],
#         label=category
#         if category not in plt.gca().get_legend_handles_labels()[1]
#         else "",
#     )
# plt.title("Delay Classification by Category")
# plt.xlabel("Packet Interval Index")
# plt.ylabel("Delay (seconds)")
# plt.grid(True)
# plt.legend()
# plt.savefig("delay_classification_scatter.png")
# plt.show()
# print("Scatter plot saved as 'delay_classification_scatter.png'.")


# --- Vectorized Scatter Plot for Delay Classification ---

print("Generating vectorized scatter plot for delay classification...")

# Convert delays and categories to numpy arrays for efficient indexing
delays_np = np.array(delays)
indices_np = np.arange(len(delays))
categories_np = np.array(delay_categories)

plt.figure(figsize=(12, 6))

# Plot one scatter per category
for category, color in color_map.items():
    idxs = indices_np[categories_np == category]
    plt.scatter(
        idxs, delays_np[categories_np == category], color=color, label=category, s=10
    )  # s controls marker size

plt.title("Delay Classification by Category (Vectorized)")
plt.xlabel("Packet Interval Index")
plt.ylabel("Delay (seconds)")
plt.grid(True)
plt.legend()
plt.savefig("delay_classification_scatter_vectorized.png")
plt.show()
print("Vectorized scatter plot saved as 'delay_classification_scatter_vectorized.png'.")


# 2. Bar Chart: Count of intervals in each category
print("Generating bar chart for delay category counts...")
category_counts = Counter(delay_categories)
categories = list(category_counts.keys())
counts = [category_counts[cat] for cat in categories]
colors = [color_map[cat] for cat in categories]

plt.figure(figsize=(8, 6))
plt.bar(categories, counts, color=colors)
plt.title("Delay Category Counts")
plt.xlabel("Delay Category")
plt.ylabel("Number of Intervals")
plt.grid(axis="y")
plt.savefig("delay_classification_bar.png")
plt.show()
print("Bar chart saved as 'delay_classification_bar.png'.")

# --- Additional Textual Output ---
print("\nDelay Category Breakdown:")
for category, count in category_counts.items():
    print(f"{category}: {count} intervals")
