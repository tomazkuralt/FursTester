using System;
using System.Collections.Generic;
using System.Text;

namespace FursTester
{
    public static class Extensions
    {

        public static string ExObjectToJson<T>(this T data)
        {
            var res = System.Text.Json.JsonSerializer.Serialize(data);

            return res;
        }
    }
}
