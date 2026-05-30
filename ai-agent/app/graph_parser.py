import json
import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network

def extract_dynamic_objects(data, found_vars):
    """
    Hàm đệ quy quét qua toàn bộ cấu trúc JSON phức tạp (body, path, query)
    để gom tất cả các thuộc tính 'DynamicObject' vào mảng found_vars.
    """
    if isinstance(data, dict):
        if "DynamicObject" in data:
            found_vars.append(data["DynamicObject"]["variableName"])
        for key, value in data.items():
            extract_dynamic_objects(value, found_vars)
    elif isinstance(data, list):
        for item in data:
            extract_dynamic_objects(item, found_vars)

def build_api_dependency_graph(grammar_path):
    G = nx.DiGraph()
    
    # 1. Đọc dữ liệu JSON
    with open(grammar_path, 'r', encoding='utf-8') as f:
        grammar = json.load(f)
        
    requests = grammar.get('Requests', [])
    
    # Bước 1: Duyệt qua tất cả API để tạo Node (Đỉnh)
    for req in requests:
        endpoint = req['id']['endpoint']
        method = req['id']['method'].upper()
        
        # Tạo tên node chuẩn hóa, ví dụ: "POST /Category"
        node_id = f"{method} {endpoint}"
        G.add_node(node_id, endpoint=endpoint, method=method)

    # Bước 2: Quét tìm DynamicObject để tạo Edge (Cạnh)
    for req in requests:
        consumer_endpoint = req['id']['endpoint']
        consumer_method = req['id']['method'].upper()
        consumer_node = f"{consumer_method} {consumer_endpoint}"
        
        # Quét lấy tất cả biến phụ thuộc của API này
        dynamic_vars = []
        extract_dynamic_objects(req, dynamic_vars)
        
        for var_name in dynamic_vars:
            # Biến có dạng: "_Category_post_id" -> Cần map ngược về "POST /Category"
            parts = var_name.lstrip('_').split('_')
            if len(parts) >= 3:
                resource_name = parts[0]           # "Category"
                producer_method = parts[1].upper() # "POST"
                
                # Tái tạo tên Node Producer
                producer_node = f"{producer_method} /{resource_name}"
                
                # Nối mũi tên (Edge) từ API Sinh ra (Producer) -> API Nhận (Consumer)
                if producer_node in G.nodes:
                    G.add_edge(producer_node, consumer_node, dependency_var=var_name, label=var_name)
                else:
                    print(f"[Cảnh báo] Không tìm thấy Producer {producer_node} cho biến {var_name}")

    return G

# --- CÁC HÀM VẼ ĐỒ THỊ BỔ SUNG ---

def draw_static_graph(G):
    """Vẽ đồ thị tĩnh bằng Matplotlib"""
    plt.figure(figsize=(12, 8))
    # Sử dụng thuật toán spring_layout để tự động đẩy các node ra xa nhau
    pos = nx.spring_layout(G, k=1.0, seed=42) 
    
    # Vẽ các node và cạnh
    nx.draw(G, pos, with_labels=True, node_color='lightblue', 
            edge_color='gray', node_size=3000, font_size=10, 
            font_weight='bold', arrows=True, arrowsize=20)
    
    # Vẽ nhãn cho các cạnh (Hiển thị tên biến truyền giữa các API)
    edge_labels = nx.get_edge_attributes(G, 'dependency_var')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8, font_color='red')
    
    plt.title("API Dependency Graph", fontsize=15)
    plt.show()

def draw_interactive_graph(G, output_filename="api_dependency_graph.html"):
    """Vẽ đồ thị tương tác bằng PyVis và xuất ra file HTML"""
    # Tạo mạng PyVis có hỗ trợ mũi tên có hướng
    net = Network(height='750px', width='100%', directed=True, bgcolor='#ffffff', font_color='black')
    
    # Chuyển đổi đồ thị từ NetworkX sang PyVis
    net.from_nx(G)
    
    # Thêm control panel để người dùng có thể tinh chỉnh vật lý của đồ thị ngay trên web
    net.show_buttons(filter_=['physics'])
    
    # Xuất file
    net.save_graph(output_filename)
    print(f"\n[Thành công] Đã xuất đồ thị tương tác ra file: {output_filename}")
    print("-> Hãy mở file này bằng trình duyệt web (Chrome, Edge...) để xem.")

# ---------------------------------

if __name__ == "__main__":
    # Thay bằng đường dẫn file grammar.json thực tế của bạn
    grammar_file = "Compile/grammar.json"
    
    try:
        api_graph = build_api_dependency_graph(grammar_file)
        
        print("====== KẾT QUẢ PHÂN TÍCH DEPENDENCY GRAPH ======")
        print(f"Tổng số API (Nodes): {api_graph.number_of_nodes()}")
        print(f"Tổng số Phụ thuộc (Edges): {api_graph.number_of_edges()}")
        print("-" * 40)
        
        print("Chi tiết luồng gọi:")
        for producer, consumer, data in api_graph.edges(data=True):
            var = data.get('dependency_var')
            print(f"[{producer}]  --tạo ra ({var})-->  [{consumer}]")
            
        # ==========================================
        # GỌI HÀM VẼ ĐỒ THỊ TẠI ĐÂY
        # ==========================================
        
        # Lựa chọn 1: Xem trực tiếp (Matplotlib)
        # draw_static_graph(api_graph) 
        
        # Lựa chọn 2: Xuất ra HTML tương tác (PyVis) - Bỏ comment để chạy
        draw_interactive_graph(api_graph)
            
    except FileNotFoundError:
        print("Không tìm thấy file grammar.json. Vui lòng kiểm tra lại đường dẫn!")