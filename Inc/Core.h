//==============================================================================
// RAII SMART HANDLE CLASSES FOR RESOURCE MANAGEMENT
//==============================================================================

/**
 * @brief Smart handle base class untuk Windows HANDLE objects
 *
 * Menggunakan RAII pattern untuk automatic resource cleanup.
 * CloseHandle() dipanggil otomatis pada destruction.
 */
class SmartHandle {
protected:
    HANDLE handle_;

public:
    /** @brief Default constructor dengan invalid handle */
    SmartHandle() : handle_(INVALID_HANDLE_VALUE) {}

    /** @brief Constructor dengan existing handle */
    explicit SmartHandle(HANDLE h) : handle_(h) {}

    /** @brief Move constructor */
    SmartHandle(SmartHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    /** @brief Move assignment operator */
    SmartHandle& operator=(SmartHandle&& other) noexcept {
        if (this != &other) {
            CloseHandle(handle_); // Cleanup existing handle
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    /** @brief Destructor - automatic cleanup */
    ~SmartHandle() {
        if (IsValid()) {
            CloseHandle(handle_);
        }
    }

    /** @brief Check if handle is valid */
    bool IsValid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != NULL; }

    /** @brief Get raw handle (use carefully) */
    HANDLE Get() const { return handle_; }

    /** @brief Release ownership tanpa cleanup */
    HANDLE Release() {
        HANDLE temp = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return temp;
    }

    /** @brief Reset dengan handle baru */
    void Reset(HANDLE h = INVALID_HANDLE_VALUE) {
        if (IsValid()) {
            CloseHandle(handle_);
        }
        handle_ = h;
    }

    // Prevent copying for safety
    SmartHandle(const SmartHandle&) = delete;
    SmartHandle& operator=(const SmartHandle&) = delete;
};

/**
 * @brief Smart handle untuk process handles (OpenProcess result)
 */
class SmartProcessHandle : public SmartHandle {
public:
    SmartProcessHandle() : SmartHandle() {}
    explicit SmartProcessHandle(HANDLE h) : SmartHandle(h) {}
    SmartProcessHandle(SmartProcessHandle&& other) noexcept = default;
    SmartProcessHandle& operator=(SmartProcessHandle&& other) noexcept = default;
};

/**
 * @brief Smart handle untuk access token handles (OpenProcessToken result)
 */
class SmartTokenHandle : public SmartHandle {
public:
    SmartTokenHandle() : SmartHandle() {}
    explicit SmartTokenHandle(HANDLE h) : SmartHandle(h) {}
    SmartTokenHandle(SmartTokenHandle&& other) noexcept = default;
    SmartTokenHandle& operator=(SmartTokenHandle&& other) noexcept = default;
};

/**
 * @brief Smart handle untuk ToolHelp snapshots (CreateToolhelp32Snapshot result)
 */
class SmartSnapshotHandle : public SmartHandle {
public:
    SmartSnapshotHandle() : SmartHandle() {}
    explicit SmartSnapshotHandle(HANDLE h) : SmartHandle(h) {}
    SmartSnapshotHandle(SmartSnapshotHandle&& other) noexcept = default;
    SmartSnapshotHandle& operator=(SmartSnapshotHandle&& other) noexcept = default;
};

/**
 * @brief RAII wrapper untuk VCL TObject (seperti TStringList)
 *
 * Menggunakan RAII pattern untuk automatic cleanup VCL objects.
 * Delete dipanggil otomatis pada destruction.
 */
class SmartStringList {
private:
    Classes::TStringList* stringList_;

public:
    /** @brief Default constructor - allocate baru TStringList */
    SmartStringList() : stringList_(new Classes::TStringList()) {}

    /** @brief Move constructor */
    SmartStringList(SmartStringList&& other) noexcept : stringList_(other.stringList_) {
        other.stringList_ = nullptr;
    }

    /** @brief Move assignment operator */
    SmartStringList& operator=(SmartStringList&& other) noexcept {
        if (this != &other) {
            delete stringList_; // Cleanup existing object
            stringList_ = other.stringList_;
            other.stringList_ = nullptr;
        }
        return *this;
    }

    /** @brief Destructor - automatic cleanup */
    ~SmartStringList() {
        delete stringList_;
    }

    /** @brief Check if object berhasil diallocate */
    bool IsAllocated() const {
        return (stringList_ != nullptr);
    }

    /** @brief Get raw pointer untuk akses langsung ke methods (use carefully) */
    Classes::TStringList* Get() const {
        return stringList_;
    }

    /** @brief Access operator untuk kemudahan penggunaan */
    Classes::TStringList* operator->() const {
        return stringList_;
    }

    // Prevent copying untuk safety - VCL objects tidak boleh dicopy
    SmartStringList(const SmartStringList&) = delete;
    SmartStringList& operator=(const SmartStringList&) = delete;
};

/**
 * @brief RAII wrapper untuk LocalAlloc/LocalFree memory management
 *
 * Menggunakan RAII pattern untuk automatic cleanup memory yang dialokasikan
 * dengan LocalAlloc(). Mencegah memory leaks dalam error paths.
 *
 * Template untuk type safety dan kompilasi statik validation.
 */
template<typename T>
class SmartLocalMemory {
private:
    T* memory_;

public:
    /** @brief Default constructor dengan NULL pointer */
    SmartLocalMemory() : memory_(nullptr) {}

    /** @brief Constructor dengan custom size allocation
     * @param size Size dalam unit T, bukan bytes
     */
    explicit SmartLocalMemory(SIZE_T size) : memory_(nullptr) {
        Allocate(size);
    }

    /** @brief Move constructor */
    SmartLocalMemory(SmartLocalMemory&& other) noexcept : memory_(other.memory_) {
        other.memory_ = nullptr;
    }

    /** @brief Move assignment operator */
    SmartLocalMemory& operator=(SmartLocalMemory&& other) noexcept {
        if (this != &other) {
            LocalFree(memory_); // Cleanup existing memory
            memory_ = other.memory_;
            other.memory_ = nullptr;
        }
        return *this;
    }

    /** @brief Destructor - automatic cleanup */
    ~SmartLocalMemory() {
        if (memory_) {
            LocalFree(memory_);
        }
    }

    /** @brief Allocate memory dengan given size */
    bool Allocate(SIZE_T size) {
        if (memory_) {
            LocalFree(memory_); // Free existing memory
        }

        if (size == 0) {
            memory_ = nullptr;
            return true;
        }

        // Calculate size in bytes and add safety margin
        SIZE_T byteSize = size * sizeof(T);
        if (byteSize / sizeof(T) != size) { // Overflow check
            return false; // Integer overflow detected
        }

        if (byteSize > 64 * 1024 * 1024) { // Reasonable 64MB limit
            return false; // Allocation too large
        }

        memory_ = static_cast<T*>(LocalAlloc(LPTR, byteSize));
        return (memory_ != nullptr);
    }

    /** @brief Check if memory is allocated */
    bool IsAllocated() const {
        return (memory_ != nullptr);
    }

    /** @brief Get raw pointer (use carefully) */
    T* Get() const {
        return memory_;
    }

    /** @brief Dereference operator untuk array-style access */
    T& operator[](SIZE_T index) {
        // Basic bounds checking in debug builds only
        assert(memory_ != nullptr && "SmartLocalMemory: Null pointer dereference");
        return memory_[index];
    }

    /** @brief Const dereference operator */
    const T& operator[](SIZE_T index) const {
        assert(memory_ != nullptr && "SmartLocalMemory: Null pointer dereference");
        return memory_[index];
    }

    /** @brief Get size assuming T is byte */
    SIZE_T GetSize() const {
        // This is unsafe - assume caller knows what they're doing
        return (memory_ != nullptr) ? LocalSize(memory_) : 0;
    }

    /** @brief Release ownership tanpa cleanup */
    T* Release() {
        T* temp = memory_;
        memory_ = nullptr;
        return temp;
    }

    /** @brief Reset ke state kosong */
    void Reset() {
        if (memory_) {
            LocalFree(memory_);
            memory_ = nullptr;
        }
    }

    // Prevent copying for safety
    SmartLocalMemory(const SmartLocalMemory&) = delete;
    SmartLocalMemory& operator=(const SmartLocalMemory&) = delete;
};
