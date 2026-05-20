import matplotlib.pyplot as plt
import networkx as nx

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.dependency_resolver import DependencyGraph

def visualize_dependency_graph(
    graph: "DependencyGraph",
    save_path: str = "output/dependency_graph.png",
    show: bool = True,
):
    """
    Vẽ dependency graph trực quan.

    Màu:
    - xanh lá: producer (POST/PUT)
    - xanh dương: GET
    - đỏ: DELETE
    - cam: unresolved node
    - tím viền đậm: vulnerable endpoint
    """

    G = nx.DiGraph()

    # -------------------------
    # Add nodes
    # -------------------------
    for node_id, node in graph.nodes.items():

        node_color = "#87CEEB"  # GET default

        if node.method in ["POST", "PUT"]:
            node_color = "#90EE90"

        elif node.method == "DELETE":
            node_color = "#FF7F7F"

        # Vulnerable endpoint
        border_width = 1
        border_color = "black"

        if node.tags:
            border_width = 3
            border_color = "purple"

        G.add_node(
            node_id,
            color=node_color,
            border_color=border_color,
            border_width=border_width,
            method=node.method,
        )

    # -------------------------
    # Add edges
    # -------------------------
    edge_labels = {}

    for edge in graph.edges:

        G.add_edge(
            edge.producer_id,
            edge.consumer_id
        )

        edge_labels[
            (
                edge.producer_id,
                edge.consumer_id
            )
        ] = (
            f"{edge.param_name}"
            f"\n({edge.resolution_type})"
        )

    # -------------------------
    # Layout
    # -------------------------
    plt.figure(figsize=(24, 18))

    pos = nx.spring_layout(
        G,
        seed=42,
        k=2
    )

    # -------------------------
    # Draw nodes
    # -------------------------
    node_colors = [
        G.nodes[n]["color"]
        for n in G.nodes
    ]

    border_colors = [
        G.nodes[n]["border_color"]
        for n in G.nodes
    ]

    border_widths = [
        G.nodes[n]["border_width"]
        for n in G.nodes
    ]

    nx.draw_networkx_nodes(
        G,
        pos,
        node_color=node_colors,
        edgecolors=border_colors,
        linewidths=border_widths,
        node_size=3000,
    )

    # -------------------------
    # Draw edges
    # -------------------------
    nx.draw_networkx_edges(
        G,
        pos,
        arrows=True,
        arrowsize=20,
        edge_color="gray",
        width=1.5,
    )

    # -------------------------
    # Labels
    # -------------------------
    short_labels = {
        node_id:
        node_id.replace(":/api/", "\n")
        for node_id in G.nodes
    }

    nx.draw_networkx_labels(
        G,
        pos,
        labels=short_labels,
        font_size=8,
    )

    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        font_size=6,
    )

    # -------------------------
    # Legend
    # -------------------------
    plt.title(
        "API Dependency Graph",
        fontsize=20
    )

    plt.axis("off")
    plt.tight_layout()

    plt.savefig(
        save_path,
        dpi=300,
        bbox_inches="tight"
    )

    if show:
        plt.show()

    print(
        f"Graph saved to {save_path}"
    )