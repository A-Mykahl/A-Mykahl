import SwiftUI

struct ContentView: View {
    @State private var billAmount = ""
    @AppStorage("isDarkMode") private var isDarkMode = false
    @FocusState private var isBillFieldFocused: Bool

    private let tipPercentages = [0.15, 0.18, 0.20]

    private var bill: Double {
        Double(billAmount) ?? 0
    }

    var body: some View {
        ZStack {
            // Background gradient
            backgroundGradient
                .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 24) {
                    headerSection
                    billInputSection
                    tipCardsSection
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                .padding(.bottom, 40)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    // MARK: - Background

    private var backgroundGradient: some View {
        LinearGradient(
            colors: isDarkMode
                ? [Color(hex: "1A1A2E"), Color(hex: "16213E")]
                : [Color(hex: "F0FFF0"), Color(hex: "E8F5E9")],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Tip Calculator")
                    .font(.system(size: 32, weight: .bold, design: .rounded))
                    .foregroundStyle(isDarkMode ? .white : Color(hex: "2E7D32"))

                Text("Split the check with ease")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            // Dark mode toggle
            Button {
                withAnimation(.easeInOut(duration: 0.3)) {
                    isDarkMode.toggle()
                }
            } label: {
                Image(systemName: isDarkMode ? "sun.max.fill" : "moon.fill")
                    .font(.title2)
                    .foregroundStyle(isDarkMode ? .yellow : Color(hex: "5C6BC0"))
                    .padding(12)
                    .background(
                        Circle()
                            .fill(isDarkMode ? Color.white.opacity(0.1) : Color.black.opacity(0.05))
                    )
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Bill Input

    private var billInputSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Bill Amount")
                .font(.headline)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Text("$")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .foregroundStyle(accentColor)

                TextField("0.00", text: $billAmount)
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .keyboardType(.decimalPad)
                    .focused($isBillFieldFocused)
                    .tint(accentColor)
            }
            .padding(20)
            .background(cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(isBillFieldFocused ? accentColor : .clear, lineWidth: 2)
            )
            .shadow(color: .black.opacity(isDarkMode ? 0.3 : 0.08), radius: 8, y: 4)
        }
    }

    // MARK: - Tip Cards

    private var tipCardsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Tip Options")
                .font(.headline)
                .foregroundStyle(.secondary)

            ForEach(tipPercentages, id: \.self) { percentage in
                tipCard(for: percentage)
            }
        }
    }

    private func tipCard(for percentage: Double) -> some View {
        let tipAmount = bill * percentage
        let total = bill + tipAmount
        let label = "\(Int(percentage * 100))%"

        return HStack(spacing: 0) {
            // Percentage badge
            VStack {
                Text(label)
                    .font(.system(size: 24, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .frame(width: 80, height: 90)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(badgeGradient(for: percentage))
            )

            // Tip and total
            HStack {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Tip")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(formatCurrency(tipAmount))
                        .font(.system(size: 20, weight: .semibold, design: .rounded))
                        .foregroundStyle(isDarkMode ? .white : .primary)
                }

                Spacer()

                VStack(alignment: .trailing, spacing: 6) {
                    Text("Total")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(formatCurrency(total))
                        .font(.system(size: 20, weight: .bold, design: .rounded))
                        .foregroundStyle(accentColor)
                }
            }
            .padding(.horizontal, 20)
        }
        .padding(8)
        .background(cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .shadow(color: .black.opacity(isDarkMode ? 0.3 : 0.08), radius: 8, y: 4)
    }

    // MARK: - Helpers

    private var accentColor: Color {
        isDarkMode ? Color(hex: "66BB6A") : Color(hex: "2E7D32")
    }

    private var cardBackground: some View {
        RoundedRectangle(cornerRadius: 16)
            .fill(isDarkMode ? Color(hex: "252540") : .white)
    }

    private func badgeGradient(for percentage: Double) -> LinearGradient {
        switch percentage {
        case 0.15:
            return LinearGradient(
                colors: [Color(hex: "43A047"), Color(hex: "66BB6A")],
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
        case 0.18:
            return LinearGradient(
                colors: [Color(hex: "00897B"), Color(hex: "26A69A")],
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
        default:
            return LinearGradient(
                colors: [Color(hex: "1565C0"), Color(hex: "42A5F5")],
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
        }
    }

    private func formatCurrency(_ value: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .currency
        formatter.locale = Locale.current
        return formatter.string(from: NSNumber(value: value)) ?? "$0.00"
    }
}

// MARK: - Color Hex Extension

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: .alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let r, g, b: Double
        switch hex.count {
        case 6:
            r = Double((int >> 16) & 0xFF) / 255
            g = Double((int >> 8) & 0xFF) / 255
            b = Double(int & 0xFF) / 255
        default:
            r = 0; g = 0; b = 0
        }
        self.init(red: r, green: g, blue: b)
    }
}

#Preview {
    ContentView()
}
