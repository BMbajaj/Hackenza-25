from scapy.all import rdpcap, TCP, IP
from collections import defaultdict
from math import pi
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import ColumnDataSource, DataTable, TableColumn, HoverTool, Select, CustomJS
from bokeh.layouts import column, row, gridplot
from bokeh.transform import cumsum
from bokeh.palettes import Category10, Turbo256
import pandas as pd
import numpy as np
import copy

# Define your pcapng file name
pcap_file = "28-1-25-bro-laptp-60ms.pcapng"

# Read all packets using Scapy
print(f"Reading packets from {pcap_file}...")
packets = rdpcap(pcap_file)
print(f"Read {len(packets)} packets.")


def identify_protocol(pkt):
    """
    Custom protocol identification function.
    Checks for common protocols by examining TCP ports.
    Returns a protocol label.
    """
    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        # Common TLS/SSL port
        if sport == 443 or dport == 443:
            return "TLS/SSL"
        # Common HTTP ports
        if sport in (80, 8080) or dport in (80, 8080):
            return "HTTP"
        # Add more heuristics as needed.
    # Fallback: use the last layer's name
    return pkt.lastlayer().name


print("Analyzing delta times per protocol...")
# Compute delta time manually and group by protocol
protocol_delta_sum = defaultdict(float)
prev_time = None
for pkt in packets:
    if prev_time is None:
        prev_time = float(pkt.time)  # Convert to float
        continue
    delta_time = float(pkt.time) - prev_time  # Convert to float
    prev_time = float(pkt.time)  # Convert to float
    proto = identify_protocol(pkt)
    protocol_delta_sum[proto] += delta_time

# Calculate the total delta time across all protocols
total_delta = sum(protocol_delta_sum.values())

print("Tracking conversations per protocol...")
##############################################
# Track conversations per protocol
##############################################
# Track conversations (src_ip, dst_ip) per protocol
protocol_conversations = defaultdict(lambda: defaultdict(int))

for pkt in packets:
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = identify_protocol(pkt)
        
        # Create a conversation key (source IP, destination IP)
        conv_key = f"{src_ip} → {dst_ip}"
        
        # Increment conversation count for this protocol
        protocol_conversations[proto][conv_key] += 1

print("Creating bar chart...")
##############################################
# 1. Bar Chart (only protocols >=5% threshold)
##############################################
# Only include protocols with sum >= 5% of total_delta.
bar_data = {
    proto: float(dt) for proto, dt in protocol_delta_sum.items() if dt >= 0.05 * total_delta
}
bar_protocols = list(bar_data.keys())
bar_delta_sums = [bar_data[proto] for proto in bar_protocols]

bar_source = ColumnDataSource(
    data=dict(protocols=bar_protocols, delta_sums=bar_delta_sums)
)

bar_chart = figure(
    x_range=bar_protocols,
    title="Sum of Delta Time per Protocol (>=5% threshold)",
    x_axis_label="Protocol",
    y_axis_label="Sum of Delta Time (seconds)",
    height=400,
    width=800,
)
bar_chart.vbar(
    x="protocols", top="delta_sums", width=0.5, source=bar_source, color="navy"
)
bar_chart.xgrid.grid_line_color = None
bar_chart.y_range.start = 0
bar_chart.xaxis.major_label_orientation = 1

# Save bar chart
output_file("plot6.html")
save(bar_chart)
print("Bar chart saved as 'plot6.html'.")

print("Creating data table...")
##############################################
# 2. Data Table (all protocols, ordered)
##############################################
table_data = pd.DataFrame(
    {
        "Protocol": list(protocol_delta_sum.keys()),
        "Sum of Delta Time (s)": [float(dt) for dt in protocol_delta_sum.values()],
    }
)
table_data["Percentage (%)"] = table_data["Sum of Delta Time (s)"] / total_delta * 100

# Round to three decimal places
table_data["Sum of Delta Time (s)"] = table_data["Sum of Delta Time (s)"].round(3)
table_data["Percentage (%)"] = table_data["Percentage (%)"].round(3)

# Order by descending sum of delta time
table_data = table_data.sort_values(by="Sum of Delta Time (s)", ascending=False)
table_source = ColumnDataSource(table_data)

columns = [
    TableColumn(field="Protocol", title="Protocol"),
    TableColumn(field="Sum of Delta Time (s)", title="Sum of Delta Time (s)"),
    TableColumn(field="Percentage (%)", title="Percentage (%)"),
]
data_table = DataTable(source=table_source, columns=columns, width=500, height=280)

# Save data table in its own HTML file (wrapped in a layout)
table_layout = column(data_table)
output_file("plot5.html")
save(table_layout)
print("Data table saved as 'plot5.html'.")

print("Creating pie chart with increased size...")
##############################################
# 3. Pie Chart (all protocols, no threshold) - MODIFIED FOR LARGER SIZE
##############################################
pie_data = pd.DataFrame(
    {
        "protocol": list(protocol_delta_sum.keys()),
        "delta_sum": [float(dt) for dt in protocol_delta_sum.values()],
    }
)
pie_data["angle"] = pie_data["delta_sum"] / total_delta * 2 * pi
pie_data["percentage"] = pie_data["delta_sum"] / total_delta * 100

# Color coding: use Category10 palette, repeat if necessary.
num_protocols = len(pie_data)
palette = (
    Category10[10]
    if num_protocols <= 10
    else Category10[10] * ((num_protocols // 10) + 1)
)
pie_data["color"] = palette[:num_protocols]

pie_source = ColumnDataSource(pie_data)

# INCREASED SIZE of pie chart (from 400x400 to 600x600)
pie_chart = figure(
    title="Percentage of Delta Time per Protocol",
    height=600,  # Increased from 400
    width=600,   # Increased from 400
    toolbar_location=None,
    tools="hover",
    tooltips="@protocol: @percentage{0.2f}%",
)

# Move chart center point to give more room for legend
pie_chart.wedge(
    x=0,          # Center X
    y=0,          # Center Y (moved from 1 to 0)
    radius=0.4,   
    start_angle=cumsum("angle", include_zero=True),
    end_angle=cumsum("angle"),
    line_color="white",
    fill_color="color",
    legend_field="protocol",
    source=pie_source,
)

# Adjust legend position to prevent clipping
pie_chart.legend.location = "top_right"  # Position legend outside
pie_chart.legend.background_fill_alpha = 0.7  # Make legend background translucent
pie_chart.legend.border_line_color = "black"  # Add a border to the legend
pie_chart.legend.border_line_width = 1
pie_chart.legend.label_text_font_size = "8pt"  # Reduce font size if needed

pie_chart.axis.axis_label = None
pie_chart.axis.visible = False
pie_chart.grid.grid_line_color = None

# Save pie chart
output_file("plot4.html")
save(pie_chart)
print("Larger pie chart saved as 'plot4.html'.")

print("Creating top conversations charts...")
##############################################
# 4. Top 5 Conversations per Protocol
##############################################

# Function to create a conversation chart for a protocol
def create_conversation_chart(protocol, conv_data):
    # Get top 5 conversations by packet count
    top_5_convs = sorted(conv_data.items(), key=lambda x: x[1], reverse=True)[:5]
    
    if not top_5_convs:
        return None  # Skip if no conversations for this protocol
    
    conv_names = [conv[0] for conv in top_5_convs]
    packet_counts = [int(conv[1]) for conv in top_5_convs]  # Convert to int
    
    # Create a color palette for this chart
    colors = Turbo256[::51][:len(top_5_convs)]  # Get evenly spaced colors
    
    # Create the chart
    source = ColumnDataSource(data=dict(
        conversations=conv_names,
        packets=packet_counts,
        color=colors
    ))
    
    p = figure(
        x_range=conv_names,
        title=f"Top 5 Conversations for {protocol}",
        x_axis_label="Conversation (Source → Destination)",
        y_axis_label="Packet Count",
        height=300,
        width=600,
        toolbar_location="right"
    )
    
    # Add hover tool for detailed information
    hover = HoverTool(
        tooltips=[
            ("Conversation", "@conversations"),
            ("Packets", "@packets"),
        ]
    )
    p.add_tools(hover)
    
    # Add bars
    p.vbar(
        x="conversations", 
        top="packets", 
        width=0.8, 
        source=source,
        color="color",
        line_color="white"
    )
    
    p.xgrid.grid_line_color = None
    p.y_range.start = 0
    p.xaxis.major_label_orientation = pi/3  # Rotate labels for better readability
    
    # Return the chart
    return p

# Create conversation data tables
def create_conversation_table(protocol, conv_data):
    # Get top 5 conversations by packet count
    top_5_convs = sorted(conv_data.items(), key=lambda x: x[1], reverse=True)[:5]
    
    if not top_5_convs:
        return None  # Skip if no conversations for this protocol
    
    # Create a DataFrame for the table
    df = pd.DataFrame({
        "Conversation": [conv[0] for conv in top_5_convs],
        "Packet Count": [int(conv[1]) for conv in top_5_convs],  # Convert to int
    })
    
    source = ColumnDataSource(df)
    
    # Define columns
    columns = [
        TableColumn(field="Conversation", title="Source → Destination"),
        TableColumn(field="Packet Count", title="Packet Count"),
    ]
    
    # Create the table
    data_table = DataTable(
        source=source, 
        columns=columns, 
        width=600, 
        height=150,
        index_position=None
    )
    
    return data_table

# Create a chart and table for each protocol with sufficient data
all_charts = []
for protocol, conversations in protocol_conversations.items():
    if len(conversations) >= 1:  # Only include protocols with at least one conversation
        chart = create_conversation_chart(protocol, conversations)
        table = create_conversation_table(protocol, conversations)
        
        if chart and table:
            # Combine chart and table
            layout = column(chart, table)
            all_charts.append(layout)

# Arrange all charts in a grid
# if all_charts:
#     grid = gridplot(all_charts, ncols=1)
    
#     # Save the conversation charts
#     output_file("top_conversations.html")
#     save(grid)
#     print("Top conversations charts saved as 'top_conversations.html'.")
# else:
#     print("No conversation data to visualize.")

print("Creating dashboard...")
##############################################
# 5. Combined Dashboard - Creating fresh copies of charts
##############################################
# For the combined dashboard, we need to recreate all the charts to avoid the "already in a doc" error

# Recreate bar chart
bar_source_dash = ColumnDataSource(
    data=dict(protocols=bar_protocols, delta_sums=bar_delta_sums)
)

bar_chart_dash = figure(
    x_range=bar_protocols,
    title="Sum of Delta Time per Protocol (>=5% threshold)",
    x_axis_label="Protocol",
    y_axis_label="Sum of Delta Time (seconds)",
    height=400,
    width=800,
)
bar_chart_dash.vbar(
    x="protocols", top="delta_sums", width=0.5, source=bar_source_dash, color="navy"
)
bar_chart_dash.xgrid.grid_line_color = None
bar_chart_dash.y_range.start = 0
bar_chart_dash.xaxis.major_label_orientation = 1

# Recreate pie chart with larger size
pie_source_dash = ColumnDataSource(pie_data)

pie_chart_dash = figure(
    title="Percentage of Delta Time per Protocol",
    height=600,  # Increased size
    width=600,   # Increased size
    toolbar_location=None,
    tools="hover",
    tooltips="@protocol: @percentage{0.2f}%",
)
pie_chart_dash.wedge(
    x=0,  # Centered at origin
    y=0,
    radius=0.4,
    start_angle=cumsum("angle", include_zero=True),
    end_angle=cumsum("angle"),
    line_color="white",
    fill_color="color",
    legend_field="protocol",
    source=pie_source_dash,
)

# Adjust legend position to prevent clipping
pie_chart_dash.legend.location = "top_right"
pie_chart_dash.legend.background_fill_alpha = 0.7
pie_chart_dash.legend.border_line_color = "black"
pie_chart_dash.legend.border_line_width = 1
pie_chart_dash.legend.label_text_font_size = "8pt"

pie_chart_dash.axis.axis_label = None
pie_chart_dash.axis.visible = False
pie_chart_dash.grid.grid_line_color = None

# Recreate data table
table_source_dash = ColumnDataSource(table_data)
columns_dash = [
    TableColumn(field="Protocol", title="Protocol"),
    TableColumn(field="Sum of Delta Time (s)", title="Sum of Delta Time (s)"),
    TableColumn(field="Percentage (%)", title="Percentage (%)"),
]
data_table_dash = DataTable(source=table_source_dash, columns=columns_dash, width=500, height=280)

# Recreate conversation charts and tables
all_charts_dash = []
for protocol, conversations in protocol_conversations.items():
    if len(conversations) >= 1:
        chart = create_conversation_chart(protocol, conversations)
        table = create_conversation_table(protocol, conversations)
        
        if chart and table:
            layout = column(chart, table)
            all_charts_dash.append(layout)

# Create dashboard layout
dashboard_layout = column(
    row(bar_chart_dash, pie_chart_dash),
    data_table_dash,
    gridplot(all_charts_dash, ncols=1)
)

# Save dashboard
# output_file("protocol_analysis_dashboard.html")
# save(dashboard_layout)
# print("Complete dashboard saved as 'protocol_analysis_dashboard.html'.")

##############################################
# 6. NEW IMPROVED: Protocol Selector Dashboard with Dropdown, Side-by-Side Layout, and Indexed IPs
##############################################
print("Creating improved protocol selector dashboard...")

# Get all protocols with conversations
protocols_with_conv = [proto for proto, conv in protocol_conversations.items() if len(conv) >= 1]

if not protocols_with_conv:
    print("No protocols with conversations to create selector dashboard.")
else:
    # Create dropdown options
    dropdown_options = [(p, p) for p in protocols_with_conv]
    
    # Create a dictionary to hold all the data for different protocols
    all_data = {}
    
    for protocol in protocols_with_conv:
        # Get top 5 conversations
        top_5_convs = sorted(protocol_conversations[protocol].items(), key=lambda x: x[1], reverse=True)[:5]
        
        if top_5_convs:
            # Create indexed IPs instead of full IP strings
            # Create a mapping from conversation to index
            conv_names = [conv[0] for conv in top_5_convs]
            conv_indices = [f"Flow {i+1}" for i in range(len(conv_names))]
            conv_packet_counts = [int(conv[1]) for conv in top_5_convs]
            
            # Create color palette
            colors = Turbo256[::51][:len(top_5_convs)]
            
            all_data[protocol] = {
                "conversations": conv_names,          # Original IP format
                "indices": conv_indices,              # Indexed format (Flow 1, Flow 2, etc.)
                "packets": conv_packet_counts,
                "colors": colors
            }
    
    # Create initial protocol selection
    selected_protocol = protocols_with_conv[0]  # Default to first protocol
    
    # Create initial sources for the chart
    chart_source = ColumnDataSource(data={
        "indices": all_data[selected_protocol]["indices"],
        "conversations": all_data[selected_protocol]["conversations"],
        "packets": all_data[selected_protocol]["packets"],
        "color": all_data[selected_protocol]["colors"]
    })
    
    # Create the chart for the selected protocol using indices
    protocol_chart = figure(
        x_range=all_data[selected_protocol]["indices"],  # Use the indices for x-axis
        title=f"Top 5 Conversations for {selected_protocol}",
        x_axis_label="Flow ID",
        y_axis_label="Packet Count",
        height=400,  # Make chart taller
        width=500,   # Make chart narrower to fit side-by-side with table
        toolbar_location="right"
    )
    
    # Add hover tool that shows both index and actual conversation IPs
    hover = HoverTool(
        tooltips=[
            ("Flow ID", "@indices"),
            ("Connection", "@conversations"),
            ("Packets", "@packets"),
        ]
    )
    protocol_chart.add_tools(hover)
    
    # Add bars using indices
    protocol_chart.vbar(
        x="indices", 
        top="packets", 
        width=0.8, 
        source=chart_source,
        color="color",
        line_color="white"
    )
    
    protocol_chart.xgrid.grid_line_color = None
    protocol_chart.y_range.start = 0
    
    # Create the table source and table with added ID column
    table_source = ColumnDataSource(pd.DataFrame({
        "ID": all_data[selected_protocol]["indices"],
        "Conversation": all_data[selected_protocol]["conversations"],
        "Packet Count": all_data[selected_protocol]["packets"]
    }))
    
    table_columns = [
        TableColumn(field="ID", title="Flow ID"),
        TableColumn(field="Conversation", title="Source → Destination"),
        TableColumn(field="Packet Count", title="Packet Count"),
    ]
    
    protocol_table = DataTable(
        source=table_source, 
        columns=table_columns, 
        width=500,      # Match width with chart
        height=400,     # Match height with chart
        index_position=None
    )
    
    # Create dropdown for protocol selection
    select = Select(
        title="Select Protocol:",
        value=selected_protocol,
        options=[(p, p) for p in protocols_with_conv],
        width=300
    )
    
    # Create a callback to update the chart and table when the dropdown selection changes
    callback = CustomJS(args=dict(
        chart=protocol_chart,
        chart_source=chart_source,
        table_source=table_source,
        all_data=all_data
    ), code="""
        // Get selected protocol
        var selected = cb_obj.value;
        var data = all_data[selected];
        
        // Update chart title
        chart.title.text = "Top 5 Conversations for " + selected;
        
        // Update chart x range (using indices)
        chart.x_range.factors = data.indices;
        
        // Update chart source data
        chart_source.data = {
            "indices": data.indices,
            "conversations": data.conversations,
            "packets": data.packets,
            "color": data.colors
        };
        chart_source.change.emit();
        
        // Update table source data
        var table_data = {
            "ID": data.indices,
            "Conversation": data.conversations,
            "Packet Count": data.packets
        };
        table_source.data = table_data;
        table_source.change.emit();
    """)
    
    # Attach the callback to the select widget
    select.js_on_change('value', callback)
    
    # Create the layout with side-by-side chart and table
    layout = column(
        select,
        row(protocol_chart, protocol_table)  # Chart and table side by side
    )
    
    # Save as a standalone HTML file
    output_file("plot7.html")
    save(layout)
    print("Improved protocol selector dashboard saved as 'plot7.html'.")

print("Analysis complete. All visualizations have been saved.")
