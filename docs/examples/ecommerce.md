# E-commerce Platform Example

Build a **complete e-commerce platform** with Ricardo Auth, featuring customer accounts, order management, and admin
functionality.

---

> **Breaking Change (v2.0.0):**
> - Authentication now uses secure cookies (`access_token`, `refresh_token`) with `HttpOnly`, `Secure`, and `SameSite`
    flags by default. You must use HTTPS in production or set `ricardo.auth.cookies.access.secure: false` for local
    development only.
> - New blocklist and rate limiting features are available (see below).
> - New `/api/auth/revoke` admin endpoint for revoking tokens (access or refresh).

## 📋 Quick Navigation

- [Overview](#overview)
- [Project Setup](#project-setup)
- [Customer Registration](#customer-registration)
- [Shopping Cart Integration](#shopping-cart-integration)
- [Order Management](#order-management)
- [Admin Dashboard](#admin-dashboard)
- [Payment Integration](#payment-integration)
- [Testing](#testing)

## Overview

**What You'll Build:**

- Customer registration and authentication
- Shopping cart with session management
- Order processing and history
- Admin dashboard for order management
- Product catalog with authentication
- Payment processing integration
- **Token blocklist and rate limiting (optional)**

**Features:**

- Guest checkout option
- Customer account management
- Order tracking
- Admin role-based access
- Password policy enforcement
- JWT-based authentication (via secure cookies)

## Project Setup

### Dependencies (pom.xml)

```xml
<dependencies>
    <!-- Ricardo Auth Starter -->
    <dependency>
        <groupId>io.github.ricardomorim</groupId>
        <artifactId>auth-spring-boot-starter</artifactId>
        <version>2.0.0</version>
    </dependency>
    
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Spring Boot JPA -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    
    <!-- Spring Boot Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- PostgreSQL -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>
    
    <!-- Validation -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    
    <!-- Redis for session management -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>
```

### Configuration

```yaml
# application.yml
spring:
  application:
    name: ecommerce-platform
  datasource:
    url: jdbc:postgresql://localhost:5432/ecommerce
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        format_sql: true
  redis:
    host: localhost
    port: 6379
    password: ${REDIS_PASSWORD:}

# Ricardo Auth Configuration
ricardo:
  auth:
    jwt:
      secret: ${JWT_SECRET}
      access-token-expiration: 604800000  # 7 days for customer convenience
      refresh-token-expiration: 1209600000 # 14 days
    controllers:
      auth:
        enabled: true
      user:
        enabled: true
    password-policy:
      min-length: 8
      require-uppercase: true
      require-lowercase: true
      require-digits: true
      require-special-chars: false  # More customer-friendly
      prevent-common-passwords: true
    # --- NEW: Blocklist and Rate Limiter ---
    token-blocklist:
      enabled: true
      type: redis   # Use 'redis' for distributed blocklist in production
    rate-limiter:
      enabled: true
      type: redis   # Use 'redis' for distributed rate limiting in production
      max-requests: 200
      time-window-ms: 60000
    # --- NEW: Cookie Security ---
    cookies:
      access:
        secure: true      # Set to false for local dev only
        http-only: true
        same-site: Strict # Strict/Lax/None
        path: /
      refresh:
        secure: true
        http-only: true
        same-site: Strict
        path: /api/auth/refresh
  redirect-https: true   # Enforce HTTPS (recommended for production)

server:
  port: 8080

# Session Configuration
server:
  servlet:
    session:
      timeout: 30m
      cookie:
        max-age: 1800
        http-only: true
        secure: true

logging:
  level:
    com.mycompany.ecommerce: INFO
    com.ricardo.auth: INFO
```

---

### Token Blocklist and Rate Limiting (NEW)

- **Token Blocklist:**
    - Prevents usage of revoked tokens (access or refresh). Supports in-memory or Redis for distributed setups.
    - Configure with `ricardo.auth.token-blocklist.type: memory|redis`.
- **Rate Limiting:**
    - Protects endpoints from brute-force and abuse. Supports in-memory or Redis for distributed setups.
    - Configure with `ricardo.auth.rate-limiter.type: memory|redis` and set `max-requests` and `time-window-ms`.

---

### Token Revocation Endpoint (NEW)

Ricardo Auth now provides an admin-only endpoint to revoke any token (access or refresh):

```http
POST /api/auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

"<token-to-revoke>"
```

- Only users with `ADMIN` role can call this endpoint.
- Works for both access and refresh tokens.

---

## Customer Registration

### Enhanced Customer Entity

```java
package com.mycompany.ecommerce.entity;

import com.ricardo.auth.domain.user.User;
import jakarta.persistence.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "customers")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Column(name = "preferred_language")
    private String preferredLanguage = "en";

    @Column(name = "marketing_consent")
    private Boolean marketingConsent = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();

    // Address information
    @OneToMany(mappedBy = "customer", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Address> addresses;

    @OneToMany(mappedBy = "customer", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Order> orders;

    // Constructors, getters, and setters
    public Customer() {
    }

    public Customer(User user, String firstName, String lastName) {
        this.user = user;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    // Getters and setters...
}
```

### Customer Registration Controller

```java
package com.mycompany.ecommerce.controller;

import com.mycompany.ecommerce.dto.*;
import com.mycompany.ecommerce.service.CustomerService;
import com.ricardo.auth.dto.TokenDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/customers")
public class CustomerRegistrationController {
    
    private final CustomerService customerService;
    
    public CustomerRegistrationController(CustomerService customerService) {
        this.customerService = customerService;
    }
    
    @PostMapping("/register")
    public ResponseEntity<CustomerRegistrationResponseDTO> registerCustomer(
            @RequestBody @Validated CustomerRegistrationRequestDTO request) {
        
        CustomerRegistrationResponseDTO response = customerService.registerCustomer(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    
    @PostMapping("/login")
    public ResponseEntity<CustomerLoginResponseDTO> customerLogin(
            @RequestBody @Validated CustomerLoginRequestDTO request) {
        
        CustomerLoginResponseDTO response = customerService.login(request);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/guest-checkout")
    public ResponseEntity<GuestCheckoutResponseDTO> createGuestCheckout(
            @RequestBody @Validated GuestCheckoutRequestDTO request) {
        
        GuestCheckoutResponseDTO response = customerService.createGuestCheckout(request);
        return ResponseEntity.ok(response);
    }
}
```

### Customer DTOs

```java
// CustomerRegistrationRequestDTO.java
public class CustomerRegistrationRequestDTO {
    @NotBlank(message = "First name is required")
    private String firstName;
    
    @NotBlank(message = "Last name is required")
    private String lastName;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Valid email is required")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
    
    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Valid phone number is required")
    private String phoneNumber;
    
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;
    
    private Boolean marketingConsent = false;
    
    // Getters and setters...
}

// CustomerRegistrationResponseDTO.java
public class CustomerRegistrationResponseDTO {
    private Long customerId;
    private String token;
    private CustomerProfileDTO customer;
    private String cartId;
    private String message;
    
    // Getters and setters...
}

// CustomerLoginResponseDTO.java
public class CustomerLoginResponseDTO {
    private String token;
    private String tokenType = "Bearer";
    private Long expiresIn;
    private CustomerProfileDTO customer;
    private Integer cartItemCount;
    private Integer wishlistItemCount;
    private OrderSummaryDTO lastOrder;
    
    // Getters and setters...
}
```

## Shopping Cart Integration

### Cart Service

```java
package com.mycompany.ecommerce.service;

import com.mycompany.ecommerce.entity.Cart;
import com.mycompany.ecommerce.entity.CartItem;
import com.mycompany.ecommerce.entity.Customer;
import com.mycompany.ecommerce.entity.Product;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class CartService {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final ProductService productService;
    private final CustomerService customerService;
    
    public CartService(RedisTemplate<String, Object> redisTemplate,
                      ProductService productService,
                      CustomerService customerService) {
        this.redisTemplate = redisTemplate;
        this.productService = productService;
        this.customerService = customerService;
    }
    
    public Cart getCart(String sessionId, String userEmail) {
        String cartKey = getCartKey(sessionId, userEmail);
        Cart cart = (Cart) redisTemplate.opsForValue().get(cartKey);
        
        if (cart == null) {
            cart = new Cart();
            cart.setSessionId(sessionId);
            if (userEmail != null) {
                Customer customer = customerService.getCustomerByEmail(userEmail);
                cart.setCustomer(customer);
            }
            saveCart(cart);
        }
        
        return cart;
    }
    
    public Cart addToCart(String sessionId, String userEmail, Long productId, Integer quantity) {
        Cart cart = getCart(sessionId, userEmail);
        Product product = productService.getProductById(productId);
        
        // Check if item already exists in cart
        CartItem existingItem = cart.getItems().stream()
            .filter(item -> item.getProduct().getId().equals(productId))
            .findFirst()
            .orElse(null);
        
        if (existingItem != null) {
            existingItem.setQuantity(existingItem.getQuantity() + quantity);
        } else {
            CartItem newItem = new CartItem();
            newItem.setProduct(product);
            newItem.setQuantity(quantity);
            newItem.setPrice(product.getPrice());
            cart.getItems().add(newItem);
        }
        
        updateCartTotals(cart);
        saveCart(cart);
        
        return cart;
    }
    
    public Cart updateCartItem(String sessionId, String userEmail, Long productId, Integer quantity) {
        Cart cart = getCart(sessionId, userEmail);
        
        CartItem item = cart.getItems().stream()
            .filter(cartItem -> cartItem.getProduct().getId().equals(productId))
            .findFirst()
            .orElseThrow(() -> new CartItemNotFoundException("Item not found in cart"));
        
        if (quantity <= 0) {
            cart.getItems().remove(item);
        } else {
            item.setQuantity(quantity);
        }
        
        updateCartTotals(cart);
        saveCart(cart);
        
        return cart;
    }
    
    public void mergeGuestCartWithCustomerCart(String guestSessionId, String customerEmail) {
        // Merge guest cart with authenticated customer cart
        Cart guestCart = getCart(guestSessionId, null);
        Cart customerCart = getCart(null, customerEmail);
        
        // Merge items
        for (CartItem guestItem : guestCart.getItems()) {
            addToCart(null, customerEmail, guestItem.getProduct().getId(), guestItem.getQuantity());
        }
        
        // Clear guest cart
        clearCart(guestSessionId, null);
    }
    
    private void updateCartTotals(Cart cart) {
        BigDecimal subtotal = cart.getItems().stream()
            .map(item -> item.getPrice().multiply(BigDecimal.valueOf(item.getQuantity())))
            .reduce(BigDecimal.ZERO, BigDecimal::add);
        
        cart.setSubtotal(subtotal);
        cart.setTax(subtotal.multiply(BigDecimal.valueOf(0.08))); // 8% tax
        cart.setTotal(cart.getSubtotal().add(cart.getTax()));
        cart.setUpdatedAt(LocalDateTime.now());
    }
    
    private String getCartKey(String sessionId, String userEmail) {
        return userEmail != null ? "cart:user:" + userEmail : "cart:session:" + sessionId;
    }
    
    private void saveCart(Cart cart) {
        String cartKey = getCartKey(cart.getSessionId(), 
            cart.getCustomer() != null ? cart.getCustomer().getUser().getEmail().getValue() : null);
        redisTemplate.opsForValue().set(cartKey, cart, 30, TimeUnit.MINUTES);
    }
}
```

### Cart Controller

```java
@RestController
@RequestMapping("/api/cart")
public class CartController {
    
    private final CartService cartService;
    
    @GetMapping
    public ResponseEntity<CartDTO> getCart(
            HttpServletRequest request,
            Authentication authentication) {
        
        String sessionId = request.getSession().getId();
        String userEmail = authentication != null ? authentication.getName() : null;
        
        Cart cart = cartService.getCart(sessionId, userEmail);
        return ResponseEntity.ok(CartDTOMapper.toDTO(cart));
    }
    
    @PostMapping("/items")
    public ResponseEntity<CartDTO> addToCart(
            @RequestBody @Validated AddToCartRequestDTO request,
            HttpServletRequest httpRequest,
            Authentication authentication) {
        
        String sessionId = httpRequest.getSession().getId();
        String userEmail = authentication != null ? authentication.getName() : null;
        
        Cart cart = cartService.addToCart(sessionId, userEmail, request.getProductId(), request.getQuantity());
        return ResponseEntity.ok(CartDTOMapper.toDTO(cart));
    }
    
    @PutMapping("/items/{productId}")
    public ResponseEntity<CartDTO> updateCartItem(
            @PathVariable Long productId,
            @RequestBody @Validated UpdateCartItemRequestDTO request,
            HttpServletRequest httpRequest,
            Authentication authentication) {
        
        String sessionId = httpRequest.getSession().getId();
        String userEmail = authentication != null ? authentication.getName() : null;
        
        Cart cart = cartService.updateCartItem(sessionId, userEmail, productId, request.getQuantity());
        return ResponseEntity.ok(CartDTOMapper.toDTO(cart));
    }
}
```

## Order Management

### Order Entity

```java
@Entity
@Table(name = "orders")
public class Order {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "order_number", unique = true, nullable = false)
    private String orderNumber;
    
    @ManyToOne
    @JoinColumn(name = "customer_id")
    private Customer customer;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status")
    private OrderStatus status = OrderStatus.PENDING;
    
    @Column(name = "subtotal", precision = 10, scale = 2)
    private BigDecimal subtotal;
    
    @Column(name = "tax", precision = 10, scale = 2)
    private BigDecimal tax;
    
    @Column(name = "shipping", precision = 10, scale = 2)
    private BigDecimal shipping;
    
    @Column(name = "total", precision = 10, scale = 2)
    private BigDecimal total;
    
    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<OrderItem> items;
    
    @Embedded
    private ShippingAddress shippingAddress;
    
    @Embedded
    private BillingAddress billingAddress;
    
    @Column(name = "payment_method")
    private String paymentMethod;
    
    @Column(name = "payment_status")
    @Enumerated(EnumType.STRING)
    private PaymentStatus paymentStatus = PaymentStatus.PENDING;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();
    
    // Constructors, getters, and setters...
}

public enum OrderStatus {
    PENDING, CONFIRMED, PROCESSING, SHIPPED, DELIVERED, CANCELLED, REFUNDED
}

public enum PaymentStatus {
    PENDING, PROCESSING, COMPLETED, FAILED, REFUNDED
}
```

### Order Service

```java
@Service
@Transactional
public class OrderService {
    
    private final OrderRepository orderRepository;
    private final CartService cartService;
    private final PaymentService paymentService;
    private final EmailService emailService;
    
    public Order createOrderFromCart(String sessionId, String userEmail, OrderRequestDTO request) {
        Cart cart = cartService.getCart(sessionId, userEmail);
        
        if (cart.getItems().isEmpty()) {
            throw new EmptyCartException("Cannot create order from empty cart");
        }
        
        // Create order
        Order order = new Order();
        order.setOrderNumber(generateOrderNumber());
        
        if (userEmail != null) {
            Customer customer = customerService.getCustomerByEmail(userEmail);
            order.setCustomer(customer);
        }
        
        // Copy cart items to order items
        for (CartItem cartItem : cart.getItems()) {
            OrderItem orderItem = new OrderItem();
            orderItem.setOrder(order);
            orderItem.setProduct(cartItem.getProduct());
            orderItem.setQuantity(cartItem.getQuantity());
            orderItem.setPrice(cartItem.getPrice());
            order.getItems().add(orderItem);
        }
        
        // Set totals
        order.setSubtotal(cart.getSubtotal());
        order.setTax(cart.getTax());
        order.setShipping(calculateShipping(order));
        order.setTotal(order.getSubtotal().add(order.getTax()).add(order.getShipping()));
        
        // Set addresses
        order.setShippingAddress(request.getShippingAddress());
        order.setBillingAddress(request.getBillingAddress());
        order.setPaymentMethod(request.getPaymentMethod());
        
        // Save order
        Order savedOrder = orderRepository.save(order);
        
        // Process payment
        try {
            PaymentResult paymentResult = paymentService.processPayment(savedOrder, request.getPaymentDetails());
            
            if (paymentResult.isSuccess()) {
                savedOrder.setPaymentStatus(PaymentStatus.COMPLETED);
                savedOrder.setStatus(OrderStatus.CONFIRMED);
                
                // Clear cart
                cartService.clearCart(sessionId, userEmail);
                
                // Send confirmation email
                emailService.sendOrderConfirmation(savedOrder);
            } else {
                savedOrder.setPaymentStatus(PaymentStatus.FAILED);
                throw new PaymentException("Payment failed: " + paymentResult.getErrorMessage());
            }
        } catch (Exception e) {
            savedOrder.setPaymentStatus(PaymentStatus.FAILED);
            throw new OrderProcessingException("Failed to process order", e);
        }
        
        return orderRepository.save(savedOrder);
    }
    
    public Page<Order> getCustomerOrders(String userEmail, Pageable pageable) {
        Customer customer = customerService.getCustomerByEmail(userEmail);
        return orderRepository.findByCustomerOrderByCreatedAtDesc(customer, pageable);
    }
    
    public Order getOrderByNumber(String orderNumber, String userEmail) {
        Order order = orderRepository.findByOrderNumber(orderNumber)
            .orElseThrow(() -> new OrderNotFoundException("Order not found: " + orderNumber));
        
        // Verify ownership
        if (userEmail != null && order.getCustomer() != null) {
            if (!order.getCustomer().getUser().getEmail().getValue().equals(userEmail)) {
                throw new UnauthorizedOrderAccessException("Access denied to order: " + orderNumber);
            }
        }
        
        return order;
    }
    
    private String generateOrderNumber() {
        return "ORD-" + System.currentTimeMillis() + "-" + ThreadLocalRandom.current().nextInt(1000, 9999);
    }
}
```

## Admin Dashboard

### Admin Controller

```java
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    
    private final OrderService orderService;
    private final CustomerService customerService;
    private final ProductService productService;
    
    @GetMapping("/dashboard")
    public ResponseEntity<AdminDashboardDTO> getDashboard() {
        AdminDashboardDTO dashboard = new AdminDashboardDTO();
        
        // Get dashboard statistics
        dashboard.setTotalOrders(orderService.getTotalOrderCount());
        dashboard.setTotalCustomers(customerService.getTotalCustomerCount());
        dashboard.setTotalRevenue(orderService.getTotalRevenue());
        dashboard.setPendingOrders(orderService.getPendingOrderCount());
        
        // Recent activity
        dashboard.setRecentOrders(orderService.getRecentOrders(5));
        dashboard.setNewCustomers(customerService.getRecentCustomers(5));
        
        return ResponseEntity.ok(dashboard);
    }
    
    @GetMapping("/orders")
    public ResponseEntity<Page<OrderDTO>> getAllOrders(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) OrderStatus status,
            @RequestParam(required = false) String customerEmail) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<Order> orders = orderService.getOrdersForAdmin(pageable, status, customerEmail);
        Page<OrderDTO> orderDTOs = orders.map(OrderDTOMapper::toDTO);
        
        return ResponseEntity.ok(orderDTOs);
    }
    
    @PutMapping("/orders/{orderId}/status")
    public ResponseEntity<OrderDTO> updateOrderStatus(
            @PathVariable Long orderId,
            @RequestBody @Validated UpdateOrderStatusRequestDTO request) {
        
        Order order = orderService.updateOrderStatus(orderId, request.getStatus());
        return ResponseEntity.ok(OrderDTOMapper.toDTO(order));
    }
    
    @GetMapping("/customers")
    public ResponseEntity<Page<CustomerDTO>> getAllCustomers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String search) {
        
        Pageable pageable = PageRequest.of(page, size);
        Page<Customer> customers = customerService.getCustomersForAdmin(pageable, search);
        Page<CustomerDTO> customerDTOs = customers.map(CustomerDTOMapper::toDTO);
        
        return ResponseEntity.ok(customerDTOs);
    }
    
    @GetMapping("/analytics/sales")
    public ResponseEntity<SalesAnalyticsDTO> getSalesAnalytics(
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd") LocalDate startDate,
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd") LocalDate endDate) {
        
        SalesAnalyticsDTO analytics = orderService.getSalesAnalytics(startDate, endDate);
        return ResponseEntity.ok(analytics);
    }
}
```

## Payment Integration

### Payment Service

```java
@Service
public class PaymentService {
    
    private final PaymentGateway paymentGateway;
    private final PaymentRepository paymentRepository;
    
    public PaymentResult processPayment(Order order, PaymentDetailsDTO paymentDetails) {
        try {
            // Create payment record
            Payment payment = new Payment();
            payment.setOrder(order);
            payment.setAmount(order.getTotal());
            payment.setPaymentMethod(paymentDetails.getPaymentMethod());
            payment.setStatus(PaymentStatus.PROCESSING);
            
            Payment savedPayment = paymentRepository.save(payment);
            
            // Process with payment gateway
            PaymentGatewayRequest gatewayRequest = new PaymentGatewayRequest();
            gatewayRequest.setAmount(order.getTotal());
            gatewayRequest.setCurrency("USD");
            gatewayRequest.setOrderNumber(order.getOrderNumber());
            gatewayRequest.setPaymentDetails(paymentDetails);
            
            PaymentGatewayResponse gatewayResponse = paymentGateway.processPayment(gatewayRequest);
            
            if (gatewayResponse.isSuccess()) {
                savedPayment.setStatus(PaymentStatus.COMPLETED);
                savedPayment.setTransactionId(gatewayResponse.getTransactionId());
                savedPayment.setGatewayResponse(gatewayResponse.getResponseCode());
                
                return PaymentResult.success(savedPayment);
            } else {
                savedPayment.setStatus(PaymentStatus.FAILED);
                savedPayment.setGatewayResponse(gatewayResponse.getErrorMessage());
                
                return PaymentResult.failure(gatewayResponse.getErrorMessage());
            }
            
        } catch (Exception e) {
            log.error("Payment processing failed for order {}", order.getOrderNumber(), e);
            return PaymentResult.failure("Payment processing failed: " + e.getMessage());
        } finally {
            paymentRepository.save(payment);
        }
    }
    
    public PaymentResult refundPayment(Long orderId, BigDecimal amount, String reason) {
        Order order = orderService.getOrderById(orderId);
        Payment originalPayment = paymentRepository.findByOrderAndStatus(order, PaymentStatus.COMPLETED)
            .orElseThrow(() -> new PaymentNotFoundException("No completed payment found for order"));
        
        // Process refund through gateway
        RefundRequest refundRequest = new RefundRequest();
        refundRequest.setTransactionId(originalPayment.getTransactionId());
        refundRequest.setAmount(amount);
        refundRequest.setReason(reason);
        
        RefundResponse refundResponse = paymentGateway.processRefund(refundRequest);
        
        if (refundResponse.isSuccess()) {
            // Create refund record
            Payment refund = new Payment();
            refund.setOrder(order);
            refund.setAmount(amount.negate()); // Negative amount for refund
            refund.setPaymentMethod(originalPayment.getPaymentMethod());
            refund.setStatus(PaymentStatus.REFUNDED);
            refund.setTransactionId(refundResponse.getRefundId());
            
            paymentRepository.save(refund);
            
            return PaymentResult.success(refund);
        } else {
            return PaymentResult.failure(refundResponse.getErrorMessage());
        }
    }
}
```

## Testing

### Integration Test

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class EcommerceIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("ecommerce_test")
            .withUsername("test")
            .withPassword("test");
    
    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7")
            .withExposedPorts(6379);
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    public void testCompleteEcommercePurchaseFlow() {
        // 1. Register customer
        CustomerRegistrationRequestDTO registrationRequest = new CustomerRegistrationRequestDTO();
        registrationRequest.setFirstName("John");
        registrationRequest.setLastName("Doe");
        registrationRequest.setEmail("john.doe@example.com");
        registrationRequest.setPassword("SecurePass@123!");
        registrationRequest.setPhoneNumber("+1234567890");
        
        ResponseEntity<CustomerRegistrationResponseDTO> registrationResponse = 
            restTemplate.postForEntity("/api/customers/register", registrationRequest, 
                CustomerRegistrationResponseDTO.class);
        
        assertThat(registrationResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        String token = registrationResponse.getBody().getToken();
        
        // 2. Add products to cart
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        
        AddToCartRequestDTO addToCartRequest = new AddToCartRequestDTO();
        addToCartRequest.setProductId(1L);
        addToCartRequest.setQuantity(2);
        
        HttpEntity<AddToCartRequestDTO> cartEntity = new HttpEntity<>(addToCartRequest, headers);
        ResponseEntity<CartDTO> cartResponse = restTemplate.postForEntity(
            "/api/cart/items", cartEntity, CartDTO.class);
        
        assertThat(cartResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(cartResponse.getBody().getItems()).hasSize(1);
        
        // 3. Create order
        OrderRequestDTO orderRequest = new OrderRequestDTO();
        orderRequest.setShippingAddress(createTestAddress());
        orderRequest.setBillingAddress(createTestAddress());
        orderRequest.setPaymentMethod("CREDIT_CARD");
        orderRequest.setPaymentDetails(createTestPaymentDetails());
        
        HttpEntity<OrderRequestDTO> orderEntity = new HttpEntity<>(orderRequest, headers);
        ResponseEntity<OrderDTO> orderResponse = restTemplate.postForEntity(
            "/api/orders", orderEntity, OrderDTO.class);
        
        assertThat(orderResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(orderResponse.getBody().getStatus()).isEqualTo(OrderStatus.CONFIRMED);
        
        // 4. Verify order history
        HttpEntity<Void> getEntity = new HttpEntity<>(headers);
        ResponseEntity<Page<OrderDTO>> historyResponse = restTemplate.exchange(
            "/api/orders/history", HttpMethod.GET, getEntity, 
            new ParameterizedTypeReference<Page<OrderDTO>>() {});
        
        assertThat(historyResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(historyResponse.getBody().getContent()).hasSize(1);
    }
    
    private ShippingAddress createTestAddress() {
        ShippingAddress address = new ShippingAddress();
        address.setStreet1("123 Main St");
        address.setCity("Anytown");
        address.setState("CA");
        address.setZipCode("12345");
        address.setCountry("US");
        return address;
    }
    
    private PaymentDetailsDTO createTestPaymentDetails() {
        PaymentDetailsDTO details = new PaymentDetailsDTO();
        details.setCardNumber("4111111111111111");
        details.setExpiryMonth("12");
        details.setExpiryYear("2025");
        details.setCvv("123");
        details.setCardholderName("John Doe");
        return details;
    }
}
```

This e-commerce example demonstrates how to build a complete online shopping platform with Ricardo Auth, featuring
customer registration, shopping cart management, order processing, and admin functionality with proper authentication
and authorization.
