# OSI Layer Visualizer

An interactive web application that demonstrates the process of packet encapsulation and decapsulation through the seven layers of the OSI (Open Systems Interconnection) model. This tool helps users understand how data is packaged and unpacked as it travels through network protocols.

## 🌟 Features

- **Interactive Packet Building**: Construct packets layer by layer, from Application to Physical
- **Real-time Visualization**: Watch packets being encapsulated and decapsulated in real-time
- **OSI Model Education**: Learn about each layer's role and header information
- **Multiple Protocols**: Support for TCP, UDP, HTTP, and custom OSI demonstrations
- **WebSocket Updates**: Live updates using SocketIO for seamless interaction
- **Hex Dump Display**: View raw packet data in hexadecimal format
- **Layer-by-Layer Analysis**: Examine headers and payloads at each OSI layer

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository** (or download the project files):
   ```bash
   git clone https://github.com/yourusername/osi-layer-visualizer.git
   cd osi-layer-visualizer
   ```

2. **Install backend dependencies**:
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Start the server**:
   ```bash
   python app.py
   ```

4. **Open your browser** and navigate to `http://localhost:5000`

The application will serve both the backend API and the frontend interface.

## 📖 Usage

1. **Select Protocol**: Choose from TCP, UDP, HTTP, or OSI demonstration mode
2. **Enter Message**: Input the data you want to send
3. **Set Network Parameters**: Configure source/destination IPs and ports
4. **Build Packet**: Click "Build Packet" to see encapsulation in action
5. **Watch Decapsulation**: Observe how each layer strips headers as data moves up the stack

### Interface Overview

- **Left Panel**: Control panel for packet configuration
- **Right Panel**: Visualization area showing current packet state
- **Bottom Panel**: Detailed layer information and hex dumps
- **Connection Status**: Real-time indicator of WebSocket connection

## 🏗️ Architecture

### Backend (Python/Flask)
- `app.py`: Main Flask application with SocketIO integration
- `packet_engine.py`: Pure Python packet construction engine
- `requirements.txt`: Python dependencies

### Frontend (HTML/CSS/JavaScript)
- `index.html`: Single-page application with responsive design
- Real-time updates via SocketIO
- Modern UI with dark theme and smooth animations

## 🛠️ Technologies Used

- **Backend**:
  - Flask - Web framework
  - Flask-SocketIO - Real-time communication
  - Flask-CORS - Cross-origin resource sharing
  - Scapy - Packet manipulation library

- **Frontend**:
  - Vanilla JavaScript
  - Socket.IO client
  - CSS Grid/Flexbox for layout
  - Google Fonts (JetBrains Mono, Inter)

## 📚 OSI Model Layers

1. **Physical Layer**: Raw bit transmission
2. **Data Link Layer**: MAC addresses and framing
3. **Network Layer**: IP addressing and routing
4. **Transport Layer**: TCP/UDP port management
5. **Session Layer**: Connection establishment
6. **Presentation Layer**: Data formatting and encryption
7. **Application Layer**: User interface and protocols

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by network protocol education tools
- Built with modern web technologies for accessibility
- Designed to make complex networking concepts approachable

## 📞 Support

If you have any questions or issues, please open an issue on GitHub or contact the maintainers.

---

**Note**: This is an educational tool and not intended for production network analysis. For real packet capture and analysis, consider tools like Wireshark.</content>
<parameter name="filePath">e:\NE Project\Project\README.md