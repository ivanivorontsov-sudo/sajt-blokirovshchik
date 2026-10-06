using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SiteBlocker.App;

/// <summary>Мелкие помощники построения WPF-интерфейса (единый стиль, кнопки, отступы).</summary>
internal static class Ui
{
    public static readonly Brush Bg = new SolidColorBrush(Color.FromRgb(0xF5, 0xF6, 0xF8));
    public static readonly Brush Accent = new SolidColorBrush(Color.FromRgb(0xC9, 0x30, 0x2C));
    public static readonly Brush Ok = new SolidColorBrush(Color.FromRgb(0x2E, 0x7D, 0x32));
    public static readonly Brush Muted = new SolidColorBrush(Color.FromRgb(0x60, 0x66, 0x70));

    public static TextBlock Label(string text, double size = 13, bool bold = false, Brush? color = null) => new()
    {
        Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 2),
        FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, Foreground = color ?? Brushes.Black,
    };

    public static Button Btn(string text, RoutedEventHandler onClick, bool primary = false)
    {
        var b = new Button
        {
            Content = text, Padding = new Thickness(14, 8, 14, 8), Margin = new Thickness(0, 6, 0, 0),
            FontSize = 13, Cursor = System.Windows.Input.Cursors.Hand, BorderThickness = new Thickness(0),
            Foreground = primary ? Brushes.White : Brushes.Black,
            Background = primary ? Accent : new SolidColorBrush(Color.FromRgb(0xE3, 0xE5, 0xE9)),
            HorizontalContentAlignment = HorizontalAlignment.Center,
        };
        b.Click += onClick;
        return b;
    }
}
