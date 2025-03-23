# mwhsrecon_tool

**Made by HuyDom**

## Giới thiệu

Công cụ **mwhsrecon_tool** cho phép thực hiện khảo sát (reconnaissance) website một cách toàn diện, bao gồm:

- Quét cổng và dịch vụ bằng **Nmap**
- Truy vấn **WHOIS** domain
- Lấy **HTTP headers** (kèm khả năng tùy chỉnh cookies)
- Lấy thông tin **SSL/TLS certificate**
- **Liệt kê thư mục** (Directory Enumeration) bất đồng bộ bằng `aiohttp`
- **Khám phá tham số URL** bằng cách crawl
- Tích hợp công cụ ngoài như **Gobuster** và **Dirb**
- Lưu kết quả dưới dạng file JSON
- Xử lý dừng đột ngột bằng `Ctrl+C` (graceful interrupt)

## Sơ đồ Mind Map (Mermaid)

Dưới đây là sơ đồ tóm tắt luồng xử lý của **mwhsrecon_tool**:

```mermaid
flowchart TB
    A((Start)) --> B{main()}
    B --> C[In ra Banner]
    B --> D[Nhập Thông Tin Target\nWordlist, Depth, Rate, Cookies]
    D --> E[Khởi tạo WebRecon]
    E --> F[run()]
    F --> F1[Nmap Scan]
    F --> F2[WHOIS Lookup]
    F --> F3[HTTP Headers]
    F --> F4[SSL Info]
    F --> F5[Directory Enum (Async)]
    F --> F6[Parameter Discovery (Crawl)]
    F --> F7[Integrate Gobuster]
    F --> F8[Integrate Dirb]
    F --> G((Kết Thúc Quét))
    G --> H[display_report()]
    H --> I[save_report()]
    I --> J((End))
