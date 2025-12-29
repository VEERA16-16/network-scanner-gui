import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def plot_open_ports_tkinter(target, open_ports, frame):
    """
    Plots open ports on a target inside a tkinter frame.
    open_ports should be a list of tuples [(port, service), ...]
    """
    if not open_ports:
        return
    ports = [p[0] for p in open_ports]
    services = [str(p[1]) for p in open_ports]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(ports, [1]*len(ports), tick_label=ports, color='skyblue')
    ax.set_xlabel('Port')
    ax.set_ylabel('Open')
    ax.set_title(f'Open Ports on {target}')
    ax.set_yticklabels([])
    ax.set_ylim(0, 1.5)

    # Annotate services
    for (x, svc) in zip(ports, services):
        ax.text(x, 1.02, svc, rotation=90, fontsize=7, ha='center', va='bottom')

    fig.tight_layout()
    # Clear previous canvas widgets in frame
    for widget in frame.winfo_children():
        widget.destroy()

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill='both', expand=True)

    plt.close(fig)
