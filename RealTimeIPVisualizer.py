# RealTimeIPVisualizer
# Author(s): Dr. Patrick Lemoine

# This version visualizes IPs with a combined Z-coordinate from the 3rd and 4th octets, and the tooltip displays the full IP address and its occurrence count when hovering over a cube.

import tkinter as tk
from tkinter import ttk
import numpy as np
from collections import Counter
import matplotlib
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import threading
import queue
import time
import os

from mpl_toolkits.mplot3d import proj3d  

matplotlib.use("TkAgg")


class RealTimeIPVisualizer(tk.Tk):
    def __init__(self, ip_log_path):
        """
        Initialize the main application window and set up the visualization.
        
        Args:
            ip_log_path (str): Path to the IP log file to visualize.
        """
        super().__init__()
        self.title("3D IP Visualizer (Combined Z-axis)")
        self.geometry("900x950")

        self.ip_log_path = ip_log_path
        # Queue to safely transfer IP data between threads
        self.data_queue = queue.Queue()

        # Frame that will contain the matplotlib plot
        self.frame_plot = ttk.Frame(self)
        self.frame_plot.pack(fill=tk.BOTH, expand=True)

        # Create a matplotlib Figure and a 3D subplot
        self.fig = plt.Figure(figsize=(7, 7))
        self.ax = self.fig.add_subplot(111, projection='3d')

        # Configure the axes limits and labels
        self.ax.set_xlim(0, 255)
        self.ax.set_ylim(0, 255)
        self.ax.set_zlim(0, 65790)  # z axis is octet3*256 + octet4, max about 65790
        self.ax.set_xlabel("Octet 1")
        self.ax.set_ylabel("Octet 2")
        self.ax.set_zlabel("Combined Octet 3 & 4")
        self.ax.set_title("3D IP Visualization with Combined Z-axis")

        # Embed the matplotlib figure inside the Tkinter frame
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frame_plot)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True)

        # Add matplotlib's navigation toolbar for interactivity (zoom, rotate, pan)
        self.toolbar = NavigationToolbar2Tk(self.canvas, self.frame_plot)
        self.toolbar.update()
        self.canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        # Frame for controls (e.g., exporting image button)
        self.frame_controls = ttk.Frame(self)
        self.frame_controls.pack(fill=tk.X)

        # Export image button
        btn_save = ttk.Button(self.frame_controls, text="Export Image", command=self.save_image)
        btn_save.pack(side=tk.LEFT, padx=5, pady=5)

        self.running = True  # Control flag to stop thread when closing

        # Stores all full IP strings seen (loaded + live updates)
        self.global_ip_strings = [] 

        # Load existing IPs from file at startup
        self.load_existing_ips()

        # Start a background thread to continuously read new IPs from the log file
        self.thread = threading.Thread(target=self.data_acquisition_loop_filetail, daemon=True)
        self.thread.start()

        self.tooltip = None  # Reference to the tooltip window (if visible)

        # Bind mouse motion event on matplotlib canvas to display tooltips
        self.canvas.mpl_connect("motion_notify_event", self.on_mouse_move)

        # Start periodic plot update cycle (every 500 ms by default)
        self.after(100, self.update_plot)

        # Bind ESC key to close the application cleanly
        self.bind('<Escape>', self.on_escape_press)

    def save_image(self):
        """
        Save the current matplotlib figure as a PNG image file.
        """
        filename = "ip_visualization_export.png"
        self.fig.savefig(filename)
        print(f"Image saved as '{filename}'")

    def load_existing_ips(self):
        """
        Load IP addresses from the log file at startup and store them.
        """
        try:
            with open(self.ip_log_path, 'r') as f:
                lines = f.readlines()
            for line in lines:
                ip = line.strip()
                if ip:
                    self.global_ip_strings.append(ip)
            print(f"{len(self.global_ip_strings)} existing IPs loaded.")
        except Exception as e:
            print(f"Error loading initial IPs: {e}")

    def on_escape_press(self, event):
        """
        Handle ESC key press event to close the application.
        """
        print("Escape pressed, closing application...")
        self.on_closing()

    def data_acquisition_loop_filetail(self):
        """
        Thread target: Continuously reads new lines from the IP log file,
        putting new IP addresses into the queue.
        """
        try:
            with open(self.ip_log_path, 'r') as f:
                f.seek(0, os.SEEK_END)  # Start reading at end for live updates
                print(f"Monitoring file: {self.ip_log_path}")
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    ip = line.strip()
                    if ip:
                        print(f"New IP read: {ip}")
                        self.data_queue.put(ip)
        except Exception as e:
            print(f"File read error: {e}")
        finally:
            print("File monitoring thread stopped.")

    def ip_to_coords(self, ip_address):
        """
        Convert a full IP address string into 3D coordinates:
        x = octet 1,
        y = octet 2,
        z = octet 3 * 256 + octet 4.

        Args:
            ip_address (str): IPv4 address string

        Returns:
            tuple of int: (x, y, z) coordinates or None if malformed IP
        """
        parts = ip_address.split('.')
        if len(parts) == 4:
            try:
                o1, o2, o3, o4 = map(int, parts)
                return (o1, o2, o3 * 256 + o4)
            except ValueError:
                pass
        return None

    def update_plot(self):
        """
        Periodically update the 3D plot with the latest IP data.

        - Reads all new IPs from the queue.
        - Extends the global IP list.
        - Counts occurrences and plots cubes sized and colored by frequency.
        - Prepares data for tooltips.
        """
        updated = False
        new_ip_strs = []
        # Read all IPs currently in the queue
        while not self.data_queue.empty():
            ip_str = self.data_queue.get()
            if ip_str:
                new_ip_strs.append(ip_str)
                updated = True

        if updated:
            self.global_ip_strings.extend(new_ip_strs)

        if self.global_ip_strings:
            # Convert every IP into plot coordinates
            coords = [self.ip_to_coords(ip) for ip in self.global_ip_strings if self.ip_to_coords(ip) is not None]

            # Count frequencies of each coordinate
            counter = Counter(coords)
            unique_coords = list(counter.keys())
            frequencies = np.array([counter[c] for c in unique_coords])

            # Map each unique coordinate to its full IPs
            coord_to_ips = {}
            for ip in self.global_ip_strings:
                coord = self.ip_to_coords(ip)
                if coord:
                    coord_to_ips.setdefault(coord, []).append(ip)

            # Pick first IP for each coordinate for tooltip display
            ips_for_coords = [coord_to_ips[c][0] for c in unique_coords]

            # Clear previous plot and setup axes again
            self.ax.clear()
            self.ax.set_xlim(0, 255)
            self.ax.set_ylim(0, 255)
            self.ax.set_zlim(0, 65790)
            self.ax.set_xlabel("Octet 1")
            self.ax.set_ylabel("Octet 2")
            self.ax.set_zlabel("Combined Octet 3 & 4")
            self.ax.set_title("3D IP Visualization with Combined Z-axis")

            # Normalize frequencies for cube size and color (size range 0.5-5 units)
            min_size, max_size = 0.5, 5
            freq_norm = (frequencies - frequencies.min()) / (frequencies.max() - frequencies.min() + 1e-5)
            sizes = min_size + freq_norm * (max_size - min_size)
            dx = dy = dz = sizes

            # Use diverging colormap: blue (rare IPs) to red (frequent IPs)
            colormap = cm.get_cmap("coolwarm")
            colors = colormap(freq_norm)

            # Decompose coordinates into separate arrays for plotting
            x_coords = [c[0] for c in unique_coords]
            y_coords = [c[1] for c in unique_coords]
            z_coords = [c[2] for c in unique_coords]

            # Draw 3D bars (cubes) with respective sizes and colors
            self.ax.bar3d(x_coords, y_coords, z_coords, dx, dy, dz,
                          color=colors, alpha=0.8, shade=True)
            #print(f"Drew {len(unique_coords)} cubes with frequency-based sizes and colors.")

            # Store tooltip data: coordinate, position, size, frequency, and full IP string
            self.cube_data_for_tooltip = list(zip(unique_coords, x_coords, y_coords, z_coords,
                                                  dx, dy, dz, frequencies, ips_for_coords))

            # Refresh the plot display
            self.canvas.draw()

        # Schedule the next update to occur in 500 ms
        self.after(500, self.update_plot)

    def on_mouse_move(self, event):
        """
        Handle mouse movement on the matplotlib canvas.

        If the mouse is near a cube, display a tooltip showing the full IP and number of occurrences.
        Otherwise, hide the tooltip.
        """
        # Only respond if mouse is over the 3D plotting axes
        if event.inaxes != self.ax:
            self.hide_tooltip()
            return

        # If tooltip data is not ready, hide tooltip
        if not hasattr(self, "cube_data_for_tooltip"):
            self.hide_tooltip()
            return

        x_mouse, y_mouse = event.x, event.y
        min_dist_pixels = 20  # Threshold pixels to detect mouse near cube
        closest_info = None

        # Iterate all cubes to find the closest one to mouse pointer
        for data in self.cube_data_for_tooltip:
            coord, x, y, z, dx, dy, dz, freq, ip_str = data
            # Project cube's 3D coordinate to 2D canvas coordinate
            x2, y2, _ = proj3d.proj_transform(x, y, z, self.ax.get_proj())
            xy2d = self.ax.transData.transform((x2, y2))
            px, py = xy2d
            dist = np.hypot(px - x_mouse, py - y_mouse)
            if dist < min_dist_pixels:
                min_dist_pixels = dist
                closest_info = (ip_str, freq)

        if closest_info:
            ip_str, freq = closest_info
            widget = event.guiEvent.widget
            # Compute absolute screen position for the tooltip placement
            x_root = widget.winfo_rootx() + event.x
            y_root = widget.winfo_rooty() + event.y
            # Show tooltip near mouse pointer with IP info
            self.show_tooltip(widget, f"IP: {ip_str}\nOccurrences: {freq}", x_root, y_root)
        else:
            self.hide_tooltip()

    def show_tooltip(self, widget, text, x_root, y_root):
        """
        Create and display a tooltip window with the given text near (x_root, y_root) screen coordinates.
        """
        if self.tooltip:
            self.tooltip.destroy()
        self.tooltip = tk.Toplevel(widget)
        self.tooltip.wm_overrideredirect(True)  # Remove default window borders and decorations
        self.tooltip.wm_geometry(f"+{x_root+10}+{y_root+10}")  # Position offsets the tooltip slightly
        label = tk.Label(self.tooltip, text=text, background="#ffffe0", relief="solid",
                         borderwidth=1, font=("tahoma", "10", "normal"))
        label.pack(ipadx=1)

    def hide_tooltip(self):
        """
        Destroy the tooltip window if it exists to hide the tooltip.
        """
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def on_closing(self):
        """
        When the application is closing, ensure the background thread stops and the window is destroyed.
        """
        self.running = False
        self.destroy()


if __name__ == '__main__':
    import sys
    file_ip_log = "ips.log"

    # Create the IP log file if it does not exist (empty file)
    if not os.path.exists(file_ip_log):
        print(f"File '{file_ip_log}' does not exist. Creating empty file.")
        with open(file_ip_log, 'w') as f:
            pass

    # Run the application
    app = RealTimeIPVisualizer(file_ip_log)
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
