#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <limits>
#include <regex>
#include <ctime>
#include <iomanip>

using namespace std;

// Base64 characters
static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Function prototypes
vector<string> parseCSVLine(const string &line);
string estimatePasswordStrength(const string &password);
void displayMenu(const vector<string> &options);
int getIntegerInput();
string base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len);
string base64_encode(const std::string &input);
inline bool is_base64(unsigned char c);
string base64_decode(const std::string &encoded_string);

// Function prototypes for input validation
bool isLeapYear(int year);
bool isValidDateFormat(const string &date);
bool isValidHourFormat(const string &hour);
bool isValidCityName(const string &city);
bool isValidEmail(const string &email);

// Function prototypes to calculate current date and time
string getCurrentHour();
string getCurrentDate();

// Function prototypes to set valid input
string setValidClass();
string setValidCity(const string &message);
string setValidDate(const string &currentLocalDate);
string setValidHour(const string &currentLocalDate, const string &currentLocalHour, string inputDate);
string setValidEmail();
string setValidPassword();

class Operator
{
private:
    string encryptedPassword;
    string vigenereEncrypt(const string &password)
    {
        string key = "ffae3b1crea2d4e5"; // Key for encryption
        string encryptedPassword = password;
        for (int i = 0; i < password.length(); i++)
        {
            encryptedPassword[i] = password[i] ^ key[i % key.length()];
        }
        return base64_encode(encryptedPassword);
    }
public:
    bool login() // Returns false if going back to main menu, true if login was successful
    {
        while (true) // Loop to handle Login Menu navigation
        {
            // Display Login Menu
            cout << "Login Menu" << endl;
            vector<string> loginOptions = {
                "Press 1 for login.",
                "Press 2 for going back to main menu."};
            displayMenu(loginOptions);

            // Get user input
            int option = getIntegerInput();
            switch (option)
            {
            case 1: // Login
            {
                string username, password;

                while (true) // Loop for login attempts
                {
                    // Get username and password
                    cout << "Type username and password to login." << endl;
                    cout << "Username: ";
                    cin >> username;
                    cout << "Password: ";
                    cin >> password;

                    // Encrypt the password
                    string encryptedPassword = vigenereEncrypt(password);

                    ifstream file("operators.csv");
                    if (!file.is_open())
                    {
                        cout << "Error opening database. Please try again later." << endl;
                        exit(1);
                    }

                    // Read the file line by line
                    string line;
                    while (getline(file, line))
                    {
                        vector<string> fields = parseCSVLine(line);
                        if (fields[0] == username && fields[1] == encryptedPassword)
                        {
                            file.close();
                            cout << "Logged in successfully!" << endl;
                            return true; // Login successful
                        }
                    }

                    file.close();

                    // If login failed
                    cout << "Username or Password is incorrect." << endl;
                    while (true) // Loop to handle retry option
                    {
                        cout << "Press 1 to try again or 2 to go back to the main menu." << endl;

                        int retryOption = getIntegerInput();
                        if (retryOption == 1)
                        {
                            break; // Ask for username and password again
                        }
                        else if (retryOption == 2)
                        {
                            return false; // Return to main menu
                        }
                        else
                        {
                            cout << "Invalid input." << endl;
                        }
                    }
                }
                break;
            }
            case 2:
            {
                return false; // Return to main menu
            }
            default:
            {
                cout << "Invalid input. Please enter a valid input." << endl;
            }
            }
        }
    }
    void addTrainRide(const string &currentLocalDate, const string &currentLocalHour)
    { // Add a train ride to the database
        cout << "Please add the following information:" << endl;

        // Get the required information
        string date = setValidDate(currentLocalDate);
        string hour = setValidHour(currentLocalDate, currentLocalHour, date);
        string departureCity = setValidCity("Departure City: ");
        string arrivalCity = setValidCity("Arrival City: ");
        string trainClass = setValidClass();
        cout << "Free seats on the ride: ";
        int freeSeats = getIntegerInput();

        ofstream file("trainRides.csv", ios::app);
        if (!file.is_open())
        {
            cout << "Error opening database. Please try again later." << endl;
            exit(1);
        }
        // Write the information to the file
        file << date << ',' << hour << ',' << departureCity << ',' << arrivalCity << ',' << trainClass << ',' << freeSeats << endl;
        file.close();
    }
    void removeTrainRide(const string &currentLocalDate, const string &currentLocalHour)
    { // Remove a train ride from the database
        cout << "Please add the following information:" << endl;

        // Get the required information
        string date = setValidDate(currentLocalDate);
        string hour = setValidHour(currentLocalDate, currentLocalHour, date);
        string departureCity = setValidCity("Departure City: ");
        string arrivalCity = setValidCity("Arrival City: ");

        ifstream file("trainRides.csv");
        if (!file.is_open())
        {
            cout << "Error opening database. Please try again later." << endl;
            exit(1);
        }

        ofstream tempFile("temp.csv", ios::app);
        if (!tempFile.is_open())
        {
            cout << "Error opening database. Please try again later." << endl;
            exit(1);
        }

        // Read the file line by line and write to a temporary file
        string line;
        bool found = false;
        while (getline(file, line))
        {
            vector<string> fields = parseCSVLine(line);
            if (!(date == fields[0] && hour == fields[1] && departureCity == fields[2] && arrivalCity == fields[3]))
            {
                tempFile << line << endl;
            }
            else
            {
                found = true;
                cout << "The ride was deleted." << endl;
            }
        }
        if (found == false)
        {
            cout << "The ride has not been found." << endl;
        }

        // Close the files and replace the original file with the temporary file
        tempFile.close();
        file.close();
        remove("trainRides.csv");
        rename("temp.csv", "trainRides.csv");
    }
};

class User
{
private:
    string encryptedPassword;
    string vigenereEncrypt(const string &password)
    {
        string key = "ffae3b1crea2d4e5"; // Key for encryption
        string encryptedPassword = password;
        for (int i = 0; i < password.length(); i++)
        {
            encryptedPassword[i] = password[i] ^ key[i % key.length()];
        }
        return base64_encode(encryptedPassword);
    }
    string vigenereDecrypt(const string &encryptedPassword)
    {
        string key = "ffae3b1crea2d4e5";                           // Key for encryption
        string decodedPassword = base64_decode(encryptedPassword); // Decode Base64
        string decryptedPassword = decodedPassword;                // Initialize decryptedPassword
        for (int i = 0; i < decodedPassword.length(); i++)
        {
            decryptedPassword[i] = decodedPassword[i] ^ key[i % key.length()]; // Undo XOR
        }
        return decryptedPassword; // Return the original password
    }

public:
    bool authentication() // Returns false if going back, true if login was successful
    {
        while (true) // Loop to handle authentication menu
        {
            // Display Authentication Menu
            cout << "Authentication Menu" << endl;
            vector<string> authenticationOptions = {
                "Press 1 to authenticate.",
                "Press 2 for going back."};
            displayMenu(authenticationOptions);

            // Get user input
            int option = getIntegerInput();
            switch (option)
            {
            case 1: // Authenticate
            {
                while (true) // Loop for login attempts
                {
                    cout << "Type email and password to login." << endl;
                    string email = setValidEmail();

                    string password;
                    cout << "Password: ";
                    cin >> password;

                    ifstream file("users.csv");
                    if (!file.is_open())
                    {
                        cout << "Error opening database. Please try again later." << endl;
                        exit(1);
                    }
                    // Read the file line by line
                    string line;
                    while (getline(file, line))
                    {
                        vector<string> fields = parseCSVLine(line);
                        if (fields[2] == email && password == vigenereDecrypt(fields[3]))
                        {
                            cout << "Authentication Succesful." << endl;
                            file.close();
                            return true; // Authentication Succesful
                        }
                    }
                    file.close();
                    // If authentication failed
                    cout << "Email or Password is incorrect." << endl;
                    while (true) // Loop to handle retry option
                    {
                        cout << "Press 1 to try again or 2 to go back." << endl;

                        int retryOption = getIntegerInput();
                        if (retryOption == 1)
                        {
                            break; // Ask for email and password again
                        }
                        else if (retryOption == 2)
                        {
                            return false; // Go back
                        }
                        else
                        {
                            cout << "Invalid input. Please enter a valid input." << endl;
                        }
                    }
                }
                break;
            }
            case 2: // Go back
            {
                return false;
            }
            default:
            {
                cout << "Invalid input. Please enter a valid input." << endl;
            }
            }
        }
    }
    void createAccount() // Create a new account
    {
        while (true) // Loop to handle create account menu
        {
            // Display Create Account Menu
            cout << "Create Account Menu" << endl;
            vector<string> createAccOptions = {
                "Press 1 to create account.",
                "Press 2 for going back."};
            displayMenu(createAccOptions);

            // Get user input
            int option = getIntegerInput();
            switch (option)
            {
            case 1: // Create Account
            {
                string firstName, lastName, email, password, reEnterPassword;

                cout << "First name: ";
                cin >> firstName;

                cout << "Last name: ";
                cin >> lastName;

                email = setValidEmail();
                password = setValidPassword();

                while (true) // Loop to check if the password matches
                {
                    cout << "Re-Enter Password: ";
                    cin >> reEnterPassword;
                    if (reEnterPassword == password)
                    {
                        break;
                    }
                    else
                    {
                        cout << "Password does not match." << endl;
                    }
                }

                // Encrypt the password
                encryptedPassword = vigenereEncrypt(password);

                ofstream file("users.csv", ios::app);
                if (!file.is_open())
                {
                    cout << "Error opening database. Please try again later." << endl;
                    exit(1);
                }

                // Write the information to the file
                file << firstName << ',' << lastName << ',' << email << ',' << encryptedPassword << endl;
                cout << "Account created succesfully. Authenticate to access the user menu." << endl;
                file.close();
                return;
            }
            case 2: // Go back
            {
                return;
            }
            default:
            {
                cout << "Invalid input. Please enter a valid input." << endl;
            }
            }
        }
    }
    void searchTrainRide(const string &currentLocalDate, const string &currentLocalHour) // Search for a train ride
    {
        cout << "Please add the following information:" << endl;

        // Get the required information
        string date = setValidDate(currentLocalDate);
        string hour = setValidHour(currentLocalDate, currentLocalHour, date);
        string departureCity = setValidCity("Departure City: ");
        string arrivalCity = setValidCity("Arrival City: ");

        ifstream file("trainRides.csv");
        if (!file.is_open())
        {
            cout << "Error opening database. Please try again later." << endl;
            exit(1);
        }

        // Read the file line by line
        string line;
        bool found = false;
        while (getline(file, line))
        {
            vector<string> fields = parseCSVLine(line);
            if (date == fields[0] && hour == fields[1] && departureCity == fields[2] && arrivalCity == fields[3])
            {
                cout << "The ride was found." << endl;
                cout << "Departure City: " << fields[2] << endl;
                cout << "Arrival City: " << fields[3] << endl;
                cout << "Class: " << fields[4] << endl;
                cout << "Free Seats: " << fields[5] << endl;
                found = true;
            }
        }

        if (!found)
        {
            cout << "The ride has not been found." << endl;
        }
        file.close();
    }
    void reserveSeat(const string &currentLocalDate, const string &currentLocalHour) // Reserve a seat
    {
        cout << "Please add the following information:" << endl;

        // Get the required information
        string date = setValidDate(currentLocalDate);
        string hour = setValidHour(currentLocalDate, currentLocalHour, date);
        string departureCity = setValidCity("Departure City: ");
        string arrivalCity = setValidCity("Arrival City: ");
        string trainClass = setValidClass();
        cout << "How many seats do you want to reserve: ";
        int seats = getIntegerInput();

        ifstream file("trainRides.csv");
        if (!file.is_open())
        {
            cout << "Error opening database. Please try again later." << endl;
            exit(1);
        }

        ofstream tempFile("temp.csv", ios::app);
        if (!tempFile.is_open())
        {
            cout << "Error opening database. Please try again later." << endl;
            exit(1);
        }

        // Read the file line by line and write to a temporary file
        string line;
        bool found = false;

        while (getline(file, line))
        {
            vector<string> fields = parseCSVLine(line);
            if (date == fields[0] && hour == fields[1] && departureCity == fields[2] && arrivalCity == fields[3] && trainClass == fields[4])
            {
                if (seats <= stoi(fields[5]))
                {
                    tempFile << fields[0] << ',' << fields[1] << ',' << fields[2] << ',' << fields[3] << ',' << fields[4] << ',' << stoi(fields[5]) - seats << endl;
                    cout << "The seat was reserved." << endl;
                    found = true;
                }
                else
                {
                    cout << "Not enough free seats." << endl;
                    tempFile << line << endl;
                }
            }
            else
            {
                tempFile << line << endl;
            }
        }

        if (!found)
        {
            cout << "The ride has not been found." << endl;
        }

        // Close the files and replace the original file with the temporary file
        tempFile.close();
        file.close();
        remove("trainRides.csv");
        rename("temp.csv", "trainRides.csv");
    }
};

int main(void)
{
    cout << "Welcome to TrainRoutes!" << endl;
    bool quitMainMenu = false;
    string currentLocalDate = getCurrentDate();
    string currentLocalHour = getCurrentHour();

    while (!quitMainMenu) // Main Menu Loop
    {
        // Display Main Menu
        cout << "Main Menu" << endl;
        vector<string> mainMenuOptions = {
            "Press 1 for Operator.",
            "Press 2 for User.",
            "Press 3 to quit."};
        displayMenu(mainMenuOptions);

        // Get user input
        int option = getIntegerInput();
        switch (option)
        {
        case 1: // Operator Mode
        {
            cout << "You need to login to access the Operator Menu." << endl;
            Operator op;
            if (op.login())
            {
                bool quitOperatorMenu = false;
                while (!quitOperatorMenu) // Operator Menu Loop
                {
                    // Display Operator Menu
                    cout << "Operator Menu" << endl;
                    vector<string> operatorOptions = {
                        "Press 1 to add a train ride.",
                        "Press 2 to remove a train ride.",
                        "Press 3 to return to Main Menu."};
                    displayMenu(operatorOptions);

                    // Get user input
                    int operatorOption = getIntegerInput();
                    switch (operatorOption)
                    {
                    case 1: // Add Train Ride
                    {
                        op.addTrainRide(currentLocalDate, currentLocalHour);
                        break;
                    }
                    case 2: // Remove Train Ride
                    {
                        op.removeTrainRide(currentLocalDate, currentLocalHour);
                        break;
                    }
                    case 3: // Return to Main Menu
                    {
                        quitOperatorMenu = true;
                        break;
                    }
                    default: // Invalid input
                    {
                        cout << "Invalid input." << endl;
                        break;
                    }
                    }
                }
            }
            break;
        }

        case 2: // User Mode
        {
            User us;
            bool quitUserOptions = false;
            while (!quitUserOptions) // User Options Loop
            {
                // Display User Options
                cout << "You need to authenticate to access the User Menu." << endl;
                vector<string> userOptions = {
                    "Press 1 to create an account.",
                    "Press 2 to authenticate.",
                    "Press 3 to return to Main Menu."};
                displayMenu(userOptions);

                // Get user input
                int userOption = getIntegerInput();
                switch (userOption)
                {
                case 1: // Create Account
                {
                    us.createAccount();
                    break;
                }
                case 2: // Authenticate
                {
                    if (us.authentication())
                    {
                        cout << "User menu" << endl;
                        bool quitUserMenu = false;
                        while (!quitUserMenu) // User Menu Loop
                        {
                            // Display User Menu
                            vector<string> userMenuOptions = {
                                "Press 1 to search for a train ride.",
                                "Press 2 to reserve a seat.",
                                "Press 3 to return to Main Menu."};
                            displayMenu(userMenuOptions);

                            // Get user input
                            int userMenuOption = getIntegerInput();
                            switch (userMenuOption)
                            {
                            case 1: // Search for a Train Ride
                            {
                                us.searchTrainRide(currentLocalDate, currentLocalHour);
                                break;
                            }
                            case 2: // Reserve a Seat
                            {
                                us.reserveSeat(currentLocalDate, currentLocalHour);
                                break;
                            }
                            case 3: // Return to Main Menu
                            {
                                quitUserMenu = true;
                                break;
                            }
                            default: // Invalid input
                            {
                                cout << "Invalid input." << endl;
                                break;
                            }
                            }
                        }
                    }
                    break;
                }
                case 3: // Return to Main Menu
                {
                    quitUserOptions = true;
                    break;
                }
                default: // Invalid input
                {
                    cout << "Invalid input." << endl;
                    break;
                }
                }
            }
            break;
        }

        case 3: // Quit
        {
            cout << "Thank you for using TrainRoutes! Have a nice day!" << endl;
            quitMainMenu = true;
            break;
        }

        default: // Invalid input
        {
            cout << "Invalid input." << endl;
            break;
        }
        }
    }

    return 0;
}

// Function to parse a CSV line
vector<string> parseCSVLine(const string &line)
{
    vector<string> fields;
    size_t start = 0;
    size_t end = line.find(',');
    while (end != string::npos) // Split the line by commas
    {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
        end = line.find(',', start);
    }
    fields.push_back(line.substr(start));
    return fields;
}

// Function to check if the year is leap
bool isLeapYear(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

// Function to check if the date is valid
bool isValidDateFormat(const string &date)
{
    // Check if format matches yyyy-mm-dd
    regex pattern(R"(^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$)");
    smatch match;
    if (!regex_match(date, match, pattern))
        return false;

    // Extract year, month, and day from the string
    int year = stoi(match[1]);
    int month = stoi(match[2]);
    int day = stoi(match[3]);

    // Days in each month
    const int daysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    // Adjust for leap year in February
    int maxDays = daysInMonth[month - 1];
    if (month == 2 && isLeapYear(year))
        maxDays = 29;

    // Check if the day is within the valid range for the month
    return day <= maxDays;
}

// Function to check if the hour is valid
bool isValidHourFormat(const string &hour)
{
    regex pattern(R"(^([01]\d|2[0-3]):([0-5]\d)$)");
    return regex_match(hour, pattern);
}

// Function to get current date
string getCurrentDate()
{
    time_t now = time(nullptr);
    tm *localTime = localtime(&now);
    ostringstream dateStream;
    dateStream << put_time(localTime, "%Y-%m-%d");
    return dateStream.str();
}

// Function to get current time
string getCurrentHour()
{
    time_t now = time(nullptr);
    tm *localTime = localtime(&now);
    ostringstream timeStream;
    timeStream << put_time(localTime, "%H:%M");
    return timeStream.str();
}

// Function to validate city name
bool isValidCityName(const string &city)
{
    // Check that the first character is uppercase and the rest are lowercase
    regex pattern("^[A-Z][a-z]*$");

    return regex_match(city, pattern);
}

// Function to validate email format
bool isValidEmail(const string &email)
{
    // Regular expression for validating email addresses
    regex pattern(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return regex_match(email, pattern);
}

// Function to force user entering a valid class
string setValidClass()
{
    string trainClass;
    while (true)
    {
        cout << "Class (First/Second): ";
        cin >> trainClass;
        if (trainClass == "First" || trainClass == "Second")
        {
            return trainClass;
        }
        else
        {
            cout << "Invalid Class. ";
        }
    }
}

// Function to force user entering a valid city
string setValidCity(const string &message)
{
    string city;
    while (true)
    {
        cout << message;
        cin >> city;
        if (isValidCityName(city))
        {
            return city;
        }
        else
        {
            cout << "Invalid City. ";
        }
    }
}

// Function to force user entering a valid date
string setValidDate(const string &currentLocalDate)
{

    string date;
    while (true)
    {
        cout << "Date (yyyy-mm-dd): ";
        cin >> date;
        if (isValidDateFormat(date)) // Validate Date format
        {
            if (date >= currentLocalDate) // Check if in the future
            {
                return date;
            }
            else // Date is in the past
            {
                cout << "Date is in the past. Add a date from the future." << endl;
            }
        }
        else
        {
            cout << "Invalid input. ";
        }
    }
}

// Function to force user entering a valid hour
string setValidHour(const string &currentLocalDate, const string &currentLocalHour, string inputDate)
{
    string inputHour;
    while (true) // Requires a valid hour input
    {
        cout << "Departure Hour (hh:mm): ";
        cin >> inputHour;
        if (isValidHourFormat(inputHour)) // Validate Hour format
        {
            if (((inputHour >= currentLocalHour && inputDate == currentLocalDate) || inputDate > currentLocalDate))
            {
                return inputHour;
            }
            else
            { // Hour is in the past
                cout << "Hour is in the past. Add an hour from the future." << endl;
            }
        }
        else
        {
            cout << "Invalid input. ";
        }
    }
}

// Function to force user entering a valid email
string setValidEmail()
{
    string email;
    while (true)
    {
        cout << "Email: ";
        cin >> email;
        if (isValidEmail(email))
        {
            return email;
        }
        else
        {
            cout << "Invalid email format. Please try again.\n";
        }
    }
}

// Function to estimate password strength
string estimatePasswordStrength(const string &password)
{
    try
    {
        if (password.empty()) // Check if password is empty
        {
            throw invalid_argument("Password cannot be empty.");
        }

        // Check if password has at least one uppercase, one lowercase, one digit, one special character and is at least 8 characters long
        string normalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 ";
        bool hasUpper = false;
        bool hasLower = false;
        bool hasDigit = false;
        bool hasSpecialChar = false;
        int passwordLength = password.length();

        for (int i = 0; i < passwordLength; i++)
        {
            if (isdigit(password[i]))
            {
                hasDigit = true;
            }
            if (isupper(password[i]))
            {
                hasUpper = true;
            }
            if (islower(password[i]))
            {
                hasLower = true;
            }
            if (normalChars.find(password[i]) == string::npos)
            {
                hasSpecialChar = true;
            }
        }

        // Check password strength
        if (hasLower && hasUpper && hasDigit && hasSpecialChar && (passwordLength >= 8))
        {
            return "good";
        }
        else if ((hasLower || hasUpper) && hasSpecialChar && (passwordLength >= 6))
        {
            return "ok";
        }
        else
        {
            return "weak";
        }
    }
    catch (const invalid_argument &e) // Catch invalid argument exception
    {
        cerr << "Error: " << e.what() << endl;
        return "invalid";
    }
    catch (...) // Catch any other exceptions
    {
        cerr << "An unexpected error occurred. Try Again." << endl;
        return "invalid";
    }
}

// Function to set a valid password
string setValidPassword()
{
    string password;
    while (true)
    {
        try
        {
            cout << "Password: ";
            cin >> password;
            string strength = estimatePasswordStrength(password);
            if (strength == "good" || strength == "ok")
            {
                return password;
            }
            else if (estimatePasswordStrength(password) == "weak")
            {
                cout << "Password is too weak. Try Again." << endl;
            }
        }
        catch (...)
        {
            cerr << "An unexpected error occurred during the process." << endl;
        }
    }
}

// Function to display a menu
void displayMenu(const vector<string> &options)
{
    for (const auto &option : options)
    {
        cout << option << endl;
    }
}

// Function to get an integer input
int getIntegerInput()
{
    int input;
    while (!(cin >> input))
    {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "Invalid input. Please enter an integer." << endl;
    }
    return input;
}

// Function to encode a string to base64
string base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len)
{
    string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
            {
                ret += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
        {
            ret += base64_chars[char_array_4[j]];
        }

        while (i++ < 3)
        {
            ret += '=';
        }
    }

    return ret;
}

string base64_encode(const string &input)
{
    return base64_encode(reinterpret_cast<const unsigned char *>(input.c_str()), input.length());
}

inline bool is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

string base64_decode(const string &encoded_string)
{
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
            {
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
            {
                ret += char_array_3[i];
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
        {
            char_array_4[j] = 0;
        }

        for (j = 0; j < 4; j++)
        {
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
        {
            ret += char_array_3[j];
        }
    }

    return ret;
}